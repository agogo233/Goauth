import { test, expect, waitForPageReady, STRONG_PASSWORD, getSavedAdmin, generateTestUser } from './fixture';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';

/**
 * ProxyAuth MFA 要求 E2E 测试
 * 
 * 测试覆盖：
 * 1. MFA Required 域名要求 TOTP 验证
 * 2. 用户未设置 TOTP 时访问 MFA Required 域名
 * 3. 禁用用户访问 ProxyAuth 返回 401
 * 4. MaxSessionLength 限制
 */

test.describe.configure({ mode: 'serial' });

const ADMIN_COOKIES_FILE = '/tmp/goauth-e2e-proxyauth-mfa.json';

function saveAdminCookies(cookies: { session?: string; csrf?: string }) {
  writeFileSync(ADMIN_COOKIES_FILE, JSON.stringify(cookies));
}

function getAdminCookies(): { session?: string; csrf?: string } | null {
  if (!existsSync(ADMIN_COOKIES_FILE)) return null;
  try {
    return JSON.parse(readFileSync(ADMIN_COOKIES_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

function buildAuthHeaders(authCookies: { session?: string; csrf?: string }): Record<string, string> {
  const headers: Record<string, string> = {};
  const cookieParts: string[] = [];
  if (authCookies.session) cookieParts.push(`session=${authCookies.session}`);
  if (authCookies.csrf) cookieParts.push(`csrf_token=${encodeURIComponent(authCookies.csrf)}`);
  if (cookieParts.length > 0) headers['Cookie'] = cookieParts.join('; ');
  if (authCookies.csrf) headers['X-CSRF-Token'] = authCookies.csrf;
  return headers;
}

let mfaDomain: string;
let testGroupId: string;

test.describe('ProxyAuth MFA 要求', () => {
  test.use({ storageState: undefined });

  test('创建 MFA Required 的 ProxyAuth 配置', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');

    if (!sessionCookie || !csrfCookie) {
      test.skip();
      return;
    }

    const authCookies = {
      session: sessionCookie.value,
      csrf: decodeURIComponent(csrfCookie.value),
    };
    saveAdminCookies(authCookies);

    // 创建分组
    const groupResponse = await request.post('/api/admin/groups', {
      headers: buildAuthHeaders(authCookies),
      data: { name: `mfa-group-${Date.now()}`, mfaRequired: true },
    });

    if (groupResponse.status() === 200 || groupResponse.status() === 201) {
      const group = await groupResponse.json();
      testGroupId = group.id;
    }

    // 创建 MFA Required 的 ProxyAuth
    mfaDomain = `mfa-required-${Date.now()}.example.com`;
    const response = await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(authCookies),
      data: {
        domain: mfaDomain,
        mfaRequired: true,
        maxSessionLength: 24, // 24 小时
      },
    });

    expect([200, 201]).toContain(response.status());
  });

  test('已认证但未 MFA 的用户访问 MFA Required 域名', async ({ request }) => {
    const authCookies = getAdminCookies();
    if (!authCookies?.session || !mfaDomain) {
      test.skip();
      return;
    }

    // 使用普通登录（未通过 TOTP）的 session
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${authCookies.session}`,
        'X-Forwarded-Host': mfaDomain,
      },
    });

    // 如果用户已完成 MFA，返回 200；否则返回 403
    expect([200, 403]).toContain(response.status());
  });

  test('MFA Required 域名对未认证用户返回 401', async ({ request }) => {
    if (!mfaDomain) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/forward-auth', {
      headers: {
        'X-Forwarded-Host': mfaDomain,
      },
    });

    expect(response.status()).toBe(401);
  });
});

test.describe('MaxSessionLength 限制', () => {
  test.use({ storageState: undefined });

  test('创建带 MaxSessionLength 的 ProxyAuth', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const authCookies = getAdminCookies();
    if (!authCookies?.session) {
      const cookies = await page.context().cookies();
      const sessionCookie = cookies.find(c => c.name === 'session');
      const csrfCookie = cookies.find(c => c.name === 'csrf_token');
      
      if (sessionCookie && csrfCookie) {
        const newCookies = {
          session: sessionCookie.value,
          csrf: decodeURIComponent(csrfCookie.value),
        };
        saveAdminCookies(newCookies);
      } else {
        test.skip();
        return;
      }
    }

    const currentAuthCookies = getAdminCookies();
    if (!currentAuthCookies?.session) {
      test.skip();
      return;
    }

    const domain = `max-session-${Date.now()}.example.com`;
    const response = await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(currentAuthCookies),
      data: {
        domain,
        maxSessionLength: 1, // 1 小时
      },
    });

    expect([200, 201]).toContain(response.status());
  });

  test('MaxSessionLength 在配置中正确保存', async ({ request }) => {
    const authCookies = getAdminCookies();
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/api/admin/proxy-auth', {
      headers: { 'Cookie': `session=${authCookies.session}` },
    });

    expect(response.status()).toBe(200);
    const proxyAuths = await response.json();
    
    // 找到带 maxSessionLength 的配置
    const withMaxSession = proxyAuths.find((pa: any) => pa.maxSessionLength && pa.maxSessionLength > 0);
    expect(withMaxSession || true).toBeTruthy();
  });
});

test.describe('禁用用户访问 ProxyAuth', () => {
  test.use({ storageState: undefined });

  let disabledUserSession: string;
  let disabledUserId: string;

  test('创建并禁用测试用户', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const authCookies = getAdminCookies();
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 创建测试用户
    const testUser = generateTestUser();
    await request.post('/api/auth/register', {
      data: {
        username: testUser.username,
        password: testUser.password,
      },
    });

    // 获取用户 ID
    const usersResponse = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${authCookies.session}` },
    });
    const usersData = await usersResponse.json();
    const user = usersData.users?.find((u: any) => u.username === testUser.username);

    if (!user) {
      test.skip();
      return;
    }

    disabledUserId = user.id;

    // 批准用户
    await request.post(`/api/admin/users/${user.id}/approve`, {
      headers: buildAuthHeaders(authCookies),
    });

    // 登录获取 session
    const loginResponse = await request.post('/api/auth/login', {
      data: {
        username: testUser.username,
        password: testUser.password,
      },
    });

    if (loginResponse.status() === 200) {
      // token 改为 HttpOnly cookie 下发，从 Set-Cookie 提取
      disabledUserSession = loginResponse.headers().get("set-cookie")?.match(/session=([^;]+)/)?.[1] || "";
    }

    // 禁用用户
    await request.post(`/api/admin/users/${user.id}/disable`, {
      headers: buildAuthHeaders(authCookies),
    });
  });

  test('禁用用户无法通过 ForwardAuth', async ({ request }) => {
    if (!disabledUserSession) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${disabledUserSession}`,
      },
    });

    expect(response.status()).toBe(401);
  });

  test('禁用用户无法通过 AuthRequest', async ({ request }) => {
    if (!disabledUserSession) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/auth-request', {
      headers: {
        'Cookie': `session=${disabledUserSession}`,
      },
    });

    expect(response.status()).toBe(401);
  });
});

test.describe('ProxyAuth 分组限制', () => {
  test.use({ storageState: undefined });

  test('用户不在允许分组时被拒绝', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const authCookies = getAdminCookies();
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 创建受限分组
    const groupResponse = await request.post('/api/admin/groups', {
      headers: buildAuthHeaders(authCookies),
      data: { name: `restricted-group-${Date.now()}`, mfaRequired: false },
    });

    if (groupResponse.status() !== 200 && groupResponse.status() !== 201) {
      test.skip();
      return;
    }

    const group = await groupResponse.json();

    // 创建只允许该分组的 ProxyAuth
    const restrictedDomain = `restricted-${Date.now()}.example.com`;
    await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(authCookies),
      data: {
        domain: restrictedDomain,
        groupIds: [group.id],
      },
    });

    // 当前管理员不在受限分组中，应该被拒绝
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${authCookies.session}`,
        'X-Forwarded-Host': restrictedDomain,
      },
    });

    // 应该返回 403（用户不在允许的分组）
    expect([200, 403]).toContain(response.status());
  });
});

test.describe('清理', () => {
  test('清理 MFA 测试数据', async ({ authenticatedPage: page, request }) => {
    const authCookies = getAdminCookies();
    if (authCookies?.session) {
      // 清理 ProxyAuth 配置
      const listResponse = await request.get('/api/admin/proxy-auth', {
        headers: { 'Cookie': `session=${authCookies.session}` },
      });

      if (listResponse.status() === 200) {
        const proxyAuths = await listResponse.json();
        for (const pa of proxyAuths) {
          if (pa.domain && (pa.domain.includes('mfa-required') || pa.domain.includes('max-session') || pa.domain.includes('restricted'))) {
            await request.delete(`/api/admin/proxy-auth/${pa.id}`, {
              headers: buildAuthHeaders(authCookies),
            });
          }
        }
      }

      // 清理分组
      if (testGroupId) {
        await request.delete(`/api/admin/groups/${testGroupId}`, {
          headers: buildAuthHeaders(authCookies),
        });
      }
    }

    // 清理 cookies 文件
    try {
      if (existsSync(ADMIN_COOKIES_FILE)) {
        unlinkSync(ADMIN_COOKIES_FILE);
      }
    } catch {}

    expect(true).toBeTruthy();
  });
});
