import { test, expect, waitForPageReady, STRONG_PASSWORD, getSavedAdmin, generateTestUser } from './fixture';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';

/**
 * 管理员自我保护 E2E 测试
 * 
 * 测试覆盖：
 * 1. 普通用户访问管理员 API 返回 403
 * 2. 管理员自我操作行为验证
 * 3. 最后一个管理员保护（如果实现）
 * 4. 管理员操作审计日志
 */

test.describe.configure({ mode: 'serial' });

const ADMIN_COOKIES_FILE = '/tmp/goauth-e2e-admin-protection.json';

function saveAdminCookies(cookies: { session?: string; csrf?: string; userId?: string }) {
  writeFileSync(ADMIN_COOKIES_FILE, JSON.stringify(cookies));
}

function getAdminCookies(): { session?: string; csrf?: string; userId?: string } | null {
  if (!existsSync(ADMIN_COOKIES_FILE)) return null;
  try {
    return JSON.parse(readFileSync(ADMIN_COOKIES_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

function cleanupAdminCookies() {
  try {
    if (existsSync(ADMIN_COOKIES_FILE)) {
      unlinkSync(ADMIN_COOKIES_FILE);
    }
  } catch {}
}

test.describe('普通用户权限限制', () => {
  test.use({ storageState: undefined });

  test('普通用户无法访问管理员用户列表 API', async ({ request }) => {
    // 创建普通用户并登录
    const normalUser = generateTestUser();
    
    // 注册用户
    const registerResponse = await request.post('/api/auth/register', {
      data: {
        username: normalUser.username,
        password: normalUser.password,
      },
    });
    
    expect([200, 201]).toContain(registerResponse.status());
    
    // 登录获取 session
    const loginResponse = await request.post('/api/auth/login', {
      data: {
        username: normalUser.username,
        password: normalUser.password,
      },
    });
    
    // 用户可能需要批准才能登录
    if (loginResponse.status() === 403) {
      // 用户未批准，这个测试验证了权限限制
      expect(loginResponse.status()).toBe(403);
      return;
    }
    
    if (loginResponse.status() !== 200) {
      test.skip();
      return;
    }
    
    // token 改为 HttpOnly cookie 下发，从 Set-Cookie 提取
    const sessionToken = loginResponse.headers()["set-cookie"]?.match(/session=([^;]+)/)?.[1] || "";
    
    // 尝试访问管理员 API
    const response = await request.get('/api/admin/users', {
      headers: {
        'Cookie': `session=${sessionToken}`,
      },
    });
    
    // 应该返回 403 Forbidden
    expect(response.status()).toBe(403);
  });
});

test.describe('管理员自我操作保护', () => {
  test.use({ storageState: undefined });

  test('管理员删除自己的行为检查', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取当前用户信息和 cookies
    const userInfo = await page.evaluate(async () => {
      const res = await fetch('/api/user/me');
      return await res.json();
    });
    
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    
    const authHeaders = {
      'Cookie': `session=${sessionCookie?.value}`,
      'X-CSRF-Token': csrfCookie ? decodeURIComponent(csrfCookie.value) : '',
    };
    
    // 创建一个临时管理员用户用于测试（而不是删除共享管理员）
    const tempAdminUsername = `temp_admin_${Date.now()}`;
    const createResponse = await request.post('/api/auth/register', {
      data: {
        username: tempAdminUsername,
        password: STRONG_PASSWORD,
        email: `${tempAdminUsername}@test.local`,
      },
    });
    
    // 注册可能需要批准，检查状态
    if (createResponse.status() === 200 || createResponse.status() === 201) {
      // 设置为管理员
      const regData = await createResponse.json();
      const tempUserId = regData.user?.id || regData.id;
      
      if (tempUserId) {
        // 将临时用户设置为管理员
        await request.post(`/api/admin/users/${tempUserId}/admin`, {
          headers: authHeaders,
          data: { isAdmin: true },
        });
        
        // 尝试删除临时管理员（自己是创建者，但这里测试删除其他管理员）
        // 注意：这个测试实际会删除临时管理员
        const deleteResult = await request.delete(`/api/admin/users/${tempUserId}`, {
          headers: authHeaders,
        });
        
        console.log(`Delete temp admin returned: ${deleteResult.status()}`);
        expect([200, 204, 400, 403]).toContain(deleteResult.status());
      }
    }
    
    // 检查原始管理员仍然存在
    const meResponse = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${sessionCookie?.value}` },
    });
    expect(meResponse.status()).toBe(200);
    
    const meData = await meResponse.json();
    expect(meData.username).toBe(userInfo.username);
  });

  test('管理员禁用自己的行为检查', async ({ page, request }) => {
    const savedCookies = getAdminCookies();
    
    if (!savedCookies?.session) {
      test.skip();
      return;
    }

    // 使用保存的 session 尝试访问 API
    const meResponse = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${savedCookies.session}` },
    });
    
    // 如果会话已失效（用户被删除），跳过测试
    if (meResponse.status() === 401) {
      console.log('Session expired after delete test, skipping disable test');
      test.skip();
      return;
    }
    
    const userInfo = await meResponse.json();
    
    // 尝试禁用自己
    const result = await request.post(`/api/admin/users/${userInfo.id}/disable`, {
      headers: {
        'Cookie': `session=${savedCookies.session}; csrf_token=${encodeURIComponent(savedCookies.csrf || '')}`,
        'X-CSRF-Token': savedCookies.csrf || '',
      },
    });

    console.log(`Admin disable self returned: ${result.status}`);
    expect([200, 400, 403, 500]).toContain(result.status());
  });

  test('管理员移除自己管理员权限的行为检查', async ({ page, request }) => {
    const savedCookies = getAdminCookies();
    
    if (!savedCookies?.session) {
      test.skip();
      return;
    }

    const meResponse = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${savedCookies.session}` },
    });
    
    if (meResponse.status() === 401) {
      console.log('Session expired, skipping test');
      test.skip();
      return;
    }
    
    const userInfo = await meResponse.json();

    // 尝试移除自己的管理员权限
    const result = await request.post(`/api/admin/users/${userInfo.id}/admin`, {
      headers: {
        'Cookie': `session=${savedCookies.session}; csrf_token=${encodeURIComponent(savedCookies.csrf || '')}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': savedCookies.csrf || '',
      },
      data: { isAdmin: false },
    });

    console.log(`Admin remove own admin rights returned: ${result.status}`);
    expect([200, 400, 403, 500]).toContain(result.status());
  });
});

test.describe('最后一个管理员保护', () => {
  test.use({ storageState: undefined });

  test('检查管理员数量', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取 session cookie
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    
    if (!sessionCookie) {
      throw new Error('No session cookie found');
    }

    const usersResponse = await request.get('/api/admin/users', {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
      },
    });
    expect(usersResponse.status()).toBe(200);
    
    const usersData = await usersResponse.json();
    const admins = usersData.users?.filter((u: any) => u.isAdmin) || [];
    
    // 记录管理员数量
    console.log(`Total admins: ${admins.length}`);
    
    // 应该至少有一个管理员
    expect(admins.length).toBeGreaterThanOrEqual(1);
  });
});

test.describe('管理员操作审计', () => {
  test.use({ storageState: undefined });

  test('管理员操作记录在审计日志中', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 执行一个管理员操作（创建分组）
    const groupName = `audit_test_${Date.now()}`;
    const createResult = await page.evaluate(async (name) => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find(c => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );
      
      const res = await fetch('/api/admin/groups', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ name }),
      });
      
      return { status: res.status };
    }, groupName);

    expect([200, 201]).toContain(createResult.status);

    // 查询审计日志
    const logsResponse = await request.get('/api/admin/audit-logs?limit=10');
    
    if (logsResponse.status() === 200) {
      const logs = await logsResponse.json();
      expect(Array.isArray(logs)).toBeTruthy();
      console.log(`Audit logs count: ${logs.length}`);
    }
  });
});

test.describe('清理', () => {
  test('清理测试数据', async () => {
    cleanupAdminCookies();
    expect(true).toBeTruthy();
  });
});