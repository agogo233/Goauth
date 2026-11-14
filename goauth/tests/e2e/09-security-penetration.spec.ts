import { test as base, expect, Page, BrowserContext } from '@playwright/test';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';

/**
 * 安全渗透测试 E2E 测试
 * 
 * 测试覆盖：
 * 1. 会话劫持攻击 (Session Hijacking)
 * 2. 越权访问 (IDOR - Insecure Direct Object Reference)
 * 3. 参数篡改攻击
 * 4. 重放攻击
 * 5. Open Redirect
 * 6. 敏感信息泄露
 * 7. 认证绕过尝试
 * 8. 授权绕过尝试
 * 9. 批量操作攻击
 * 10. 路径遍历尝试
 */

// ============ 常量和辅助函数 ============

const STRONG_PASSWORD = 'Correct-Horse-Battery-Staple-2024!';
const TEST_DATA_FILE = '/tmp/goauth-e2e-penetration-data.json';
const ADMIN_STATE_FILE = '/tmp/goauth-e2e-penetration-admin.json';

interface TestData {
  user1Session?: string;
  user1Id?: string;
  user1Username?: string;
  user1Password?: string;
  user2Session?: string;
  user2Id?: string;
  user2Username?: string;
  adminSession?: string;
  adminCsrf?: string;
  adminId?: string;
  adminUsername?: string;
  testGroupId?: string;
  testClientId?: string;
}

interface AdminCredentials {
  username: string;
  password: string;
  email: string;
  session?: string;
  csrf?: string;
}

function saveTestData(data: TestData): void {
  writeFileSync(TEST_DATA_FILE, JSON.stringify(data));
}

function getTestData(): TestData | null {
  if (!existsSync(TEST_DATA_FILE)) return null;
  try {
    return JSON.parse(readFileSync(TEST_DATA_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

function getSavedAdmin(): AdminCredentials | null {
  if (!existsSync(ADMIN_STATE_FILE)) return null;
  try {
    return JSON.parse(readFileSync(ADMIN_STATE_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

function saveAdmin(creds: AdminCredentials): void {
  writeFileSync(ADMIN_STATE_FILE, JSON.stringify(creds));
}

function generateUsername(): string {
  return `pen_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

function generateEmail(username: string): string {
  return `${username}@test.example.com`;
}

async function waitForPageReady(page: Page): Promise<void> {
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(300);
}

// 创建扩展的 test fixture
type PenTestFixtures = {
  adminPage: Page;
};

const test = base.extend<PenTestFixtures>({
  adminPage: async ({ page, context }, use) => {
    // 尝试使用已保存的管理员凭据
    const savedAdmin = getSavedAdmin();
    let testData = getTestData() || {};
    
    if (savedAdmin && savedAdmin.username && savedAdmin.password) {
      // 登录已保存的管理员
      await page.goto('/#login');
      await waitForPageReady(page);
      await page.locator('#username').fill(savedAdmin.username);
      await page.locator('#password').fill(savedAdmin.password);
      await page.locator('button[type="submit"]:has-text("登录")').click();
      await page.waitForTimeout(2000);
      
      // 验证登录成功
      const isLoggedIn = await page.locator('h1:has-text("管理后台")').isVisible({ timeout: 5000 }).catch(() => false);
      
      if (isLoggedIn) {
        const cookies = await context.cookies();
        const sessionCookie = cookies.find(c => c.name === 'session');
        const csrfCookie = cookies.find(c => c.name === 'csrf_token');
        
        testData.adminSession = sessionCookie?.value;
        testData.adminCsrf = csrfCookie ? decodeURIComponent(csrfCookie.value) : undefined;
        testData.adminUsername = savedAdmin.username;
        
        // 获取用户 ID
        const meData = await page.evaluate(async () => {
          const res = await fetch('/api/user/me');
          return res.ok ? await res.json() : null;
        });
        if (meData) testData.adminId = meData.id;
        
        saveTestData(testData);
        await use(page);
        return;
      }
    }
    
    // 创建新的管理员（第一个用户自动成为管理员）
    const username = generateUsername();
    const password = STRONG_PASSWORD;
    const email = generateEmail(username);
    
    // 导航到首页并等待加载
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1000);
    
    // 点击注册链接切换到注册视图
    const registerLink = page.locator('a:has-text("注册")');
    const hasRegisterLink = await registerLink.isVisible({ timeout: 5000 }).catch(() => false);
    
    if (hasRegisterLink) {
      await registerLink.click();
      await page.waitForTimeout(500);
    } else {
      // 直接导航到注册页
      await page.goto('/#register');
      await page.waitForLoadState('networkidle');
      await page.waitForTimeout(500);
    }
    
    // 等待注册表单可见
    await page.locator('#reg-username').waitFor({ state: 'visible', timeout: 10000 });
    await page.waitForTimeout(300);
    
    await page.locator('#reg-username').fill(username);
    await page.locator('#reg-email').fill(email);
    await page.locator('#reg-password').fill(password);
    await page.locator('#reg-confirm').fill(password);
    await page.locator('button:has-text("注册")').click();
    await page.waitForTimeout(2000);
    
    // 登录
    await page.goto('/#login');
    await waitForPageReady(page);
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('button[type="submit"]:has-text("登录")').click();
    await page.waitForTimeout(2000);
    
    // 验证是管理员
    const meData = await page.evaluate(async () => {
      const res = await fetch('/api/user/me');
      return res.ok ? await res.json() : null;
    });
    
    if (!meData?.isAdmin) {
      // 数据库已有用户，新用户不是管理员
      // 尝试使用已保存的管理员重新登录
      const savedAdmin = getSavedAdmin();
      if (savedAdmin) {
        await page.goto('/#login');
        await waitForPageReady(page);
        await page.locator('#username').fill(savedAdmin.username);
        await page.locator('#password').fill(savedAdmin.password);
        await page.locator('button[type="submit"]:has-text("登录")').click();
        await page.waitForTimeout(2000);
        
        const isAdmin = await page.locator('h1:has-text("管理后台")').isVisible({ timeout: 5000 }).catch(() => false);
        if (!isAdmin) {
          // 无法登录管理员，跳过测试
          test.skip();
          return;
        }
      } else {
        // 没有保存的管理员，跳过测试
        test.skip();
        return;
      }
    }
    
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    
    testData.adminSession = sessionCookie?.value;
    testData.adminCsrf = csrfCookie ? decodeURIComponent(csrfCookie.value) : undefined;
    testData.adminId = meData.id;
    testData.adminUsername = username;
    saveTestData(testData);
    saveAdmin({ username, password, email, session: sessionCookie?.value, csrf: testData.adminCsrf });
    
    await use(page);
  },
});

test.describe.configure({ mode: 'serial' });

// ============ 1. 会话劫持攻击测试 ============

test.describe('会话劫持攻击防御', () => {
  test('初始化管理员并测试 Session Fixation 防御', async ({ adminPage: page, context }) => {
    // 确保在管理后台
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    // 获取当前 session
    const cookies = await context.cookies();
    const session = cookies.find(c => c.name === 'session');
    
    // 验证 session 存在
    expect(session?.value).toBeTruthy();
    
    // 保存测试数据
    const testData = getTestData() || {};
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    testData.adminSession = session?.value;
    testData.adminCsrf = csrfCookie ? decodeURIComponent(csrfCookie.value) : undefined;
    saveTestData(testData);
    
    // 测试：登录后 session 应该改变
    // 先登出，然后重新登录，验证 session 变化（携带 CSRF token）
    await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );
      await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrfToken } });
    });
    await context.clearCookies();
    
    const savedAdmin = getSavedAdmin();
    if (savedAdmin) {
      // 重新登录
      await page.goto('/#login');
      await waitForPageReady(page);
      await page.locator('#username').fill(savedAdmin.username);
      await page.locator('#password').fill(savedAdmin.password);
      await page.locator('button[type="submit"]:has-text("登录")').click();
      await page.waitForTimeout(2000);
      
      // 验证新 session
      const newCookies = await context.cookies();
      const newSession = newCookies.find(c => c.name === 'session');
      
      expect(newSession?.value).toBeTruthy();
      expect(newSession?.value).not.toBe(session?.value);
    }
  });

  test('过期/失效的 session 无法访问受保护资源', async ({ request }) => {
    const invalidSessions = [
      'invalid-token-12345',
      '',
      'expired-session-token',
      'a'.repeat(100),
      '<script>alert(1)</script>',
    ];
    
    for (const session of invalidSessions) {
      const response = await request.get('/api/user/me', {
        headers: { 'Cookie': `session=${session}` },
      });
      expect(response.status()).toBe(401);
    }
  });
});

// ============ 2. 越权访问测试 (IDOR) ============

test.describe('越权访问防御 (IDOR)', () => {
  test('准备测试数据 - 创建普通用户', async ({ adminPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    const testData = getTestData() || {};
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    
    testData.adminSession = sessionCookie?.value;
    testData.adminCsrf = csrfCookie ? decodeURIComponent(csrfCookie.value) : undefined;
    
    // 创建两个普通用户用于 IDOR 测试
    const user1Username = generateUsername();
    const user1Password = STRONG_PASSWORD;
    const user2Username = generateUsername();
    const user2Password = STRONG_PASSWORD;
    
    // 注册用户1
    await request.post('/api/auth/register', {
      data: { username: user1Username, password: user1Password },
    });
    
    // 注册用户2
    await request.post('/api/auth/register', {
      data: { username: user2Username, password: user2Password },
    });
    
    // 获取用户列表
    const usersResponse = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${testData.adminSession}` },
    });
    const usersData = await usersResponse.json();
    
    const user1Record = usersData.users?.find((u: any) => u.username === user1Username);
    const user2Record = usersData.users?.find((u: any) => u.username === user2Username);
    
    // 批准用户
    if (user1Record) {
      await request.post(`/api/admin/users/${user1Record.id}/approve`, {
        headers: {
          'Cookie': `session=${testData.adminSession}; csrf_token=${encodeURIComponent(testData.adminCsrf || '')}`,
          'X-CSRF-Token': testData.adminCsrf || '',
        },
      });
    }
    
    if (user2Record) {
      await request.post(`/api/admin/users/${user2Record.id}/approve`, {
        headers: {
          'Cookie': `session=${testData.adminSession}; csrf_token=${encodeURIComponent(testData.adminCsrf || '')}`,
          'X-CSRF-Token': testData.adminCsrf || '',
        },
      });
    }
    
    // 用户登录
    const login1 = await request.post('/api/auth/login', {
      data: { username: user1Username, password: user1Password },
    });
    
    const login2 = await request.post('/api/auth/login', {
      data: { username: user2Username, password: user2Password },
    });
    
    if (login1.status() === 200 && login2.status() === 200) {
      // token 改为 HttpOnly cookie 下发，从 Set-Cookie 提取
      testData.user1Session = login1.headers().get("set-cookie")?.match(/session=([^;]+)/)?.[1] || "";
      testData.user1Id = user1Record?.id;
      testData.user1Username = user1Username;
      testData.user2Session = login2.headers().get("set-cookie")?.match(/session=([^;]+)/)?.[1] || "";
      testData.user2Id = user2Record?.id;
      testData.user2Username = user2Username;
    }
    
    // 创建测试分组
    const groupResponse = await request.post('/api/admin/groups', {
      headers: {
        'Cookie': `session=${testData.adminSession}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': testData.adminCsrf || '',
      },
      data: { name: `idor-test-group-${Date.now()}` },
    });
    
    if (groupResponse.status() === 200 || groupResponse.status() === 201) {
      const groupData = await groupResponse.json();
      testData.testGroupId = groupData.id;
    }
    
    saveTestData(testData);
    expect(true).toBeTruthy();
  });

  test('普通用户无法越权访问管理员 API', async ({ request }) => {
    const testData = getTestData();
    if (!testData?.user1Session) {
      test.skip();
      return;
    }
    
    const response = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${testData.user1Session}` },
    });
    
    expect(response.status()).toBe(403);
  });

  test('普通用户无法越权修改分组数据', async ({ request }) => {
    const testData = getTestData();
    if (!testData?.user1Session || !testData?.testGroupId) {
      test.skip();
      return;
    }
    
    const response = await request.patch(`/api/admin/groups/${testData.testGroupId}`, {
      headers: {
        'Cookie': `session=${testData.user1Session}`,
        'Content-Type': 'application/json',
      },
      data: { name: 'hacked-group-name' },
    });
    
    expect([401, 403, 404]).toContain(response.status());
  });

  test('普通用户无法越权删除资源', async ({ request }) => {
    const testData = getTestData();
    if (!testData?.user1Session || !testData?.testGroupId) {
      test.skip();
      return;
    }
    
    const response = await request.delete(`/api/admin/groups/${testData.testGroupId}`, {
      headers: { 'Cookie': `session=${testData.user1Session}` },
    });
    
    expect([401, 403, 404]).toContain(response.status());
  });

  test('用户 A 无法访问用户 B 的敏感操作', async ({ request }) => {
    const testData = getTestData();
    if (!testData?.user1Session || !testData?.user2Id) {
      test.skip();
      return;
    }
    
    const response = await request.post(`/api/admin/users/${testData.user2Id}/disable`, {
      headers: { 'Cookie': `session=${testData.user1Session}` },
    });
    
    expect(response.status()).toBe(403);
  });
});

// ============ 3. 参数篡改攻击测试 ============

test.describe('参数篡改攻击防御', () => {
  test('尝试通过参数篡改提升权限', async ({ adminPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.value) : '';
    
    // 获取当前用户信息
    const meResponse = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${sessionCookie?.value}` },
    });
    const meData = await meResponse.json();
    const originalIsAdmin = meData.isAdmin;
    
    // 尝试通过 API 参数篡改提升权限
    await request.patch('/api/user/profile', {
      headers: {
        'Cookie': `session=${sessionCookie?.value}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      data: {
        name: 'Test User',
        isAdmin: true,
        role: 'admin',
      },
    });
    
    // 验证用户没有被提升为管理员
    const verifyResponse = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${sessionCookie?.value}` },
    });
    const verifyData = await verifyResponse.json();
    
    expect(verifyData.isAdmin).toBe(originalIsAdmin);
  });

  test('尝试通过参数注入绕过必填字段', async ({ adminPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    // 使用 page.evaluate 确保使用正确的 session 和 CSRF token
    const result = await page.evaluate(async () => {
      // 从 cookie 获取 CSRF token
      const getCookie = (name: string) => {
        const match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
        return match ? decodeURIComponent(match[2]) : '';
      };
      
      const csrfToken = getCookie('csrf_token');
      
      const res = await fetch('/api/admin/groups', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ name: '' }), // 空名称
      });
      
      return { status: res.status, body: await res.text() };
    });
    
    // 空名称应该返回 400 或 422（验证错误）
    expect([400, 422]).toContain(result.status);
  });

  test('尝试 SQL 注入参数', async ({ request }) => {
    const sqlPayloads = [
      "admin'--",
      "admin' OR '1'='1",
      "admin'; DROP TABLE users;--",
      "1' UNION SELECT * FROM users--",
    ];
    
    for (const payload of sqlPayloads) {
      const response = await request.post('/api/auth/login', {
        data: { username: payload, password: 'anypassword' },
      });
      
      expect([400, 401, 429]).toContain(response.status());
      
      const body = await response.text();
      expect(body.toLowerCase()).not.toContain('sql');
      expect(body.toLowerCase()).not.toContain('database');
      expect(body.toLowerCase()).not.toContain('syntax');
    }
  });

  test('尝试 NoSQL/JSON 注入参数', async ({ request }) => {
    const nosqlPayloads = [
      { username: { $ne: null }, password: { $ne: null } },
      { username: { $regex: '.*' }, password: { $regex: '.*' } },
    ];
    
    for (const payload of nosqlPayloads) {
      const response = await request.post('/api/auth/login', {
        data: payload,
      });
      
      expect([400, 401, 429]).toContain(response.status());
    }
  });
});

// ============ 4. 重放攻击测试 ============

test.describe('重放攻击防御', () => {
  test('使用过期 CSRF Token 的请求被拒绝', async ({ adminPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    const testData = getTestData();
    
    const response = await request.post('/api/admin/groups', {
      headers: {
        'Cookie': `session=${testData?.adminSession}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'expired-csrf-token-12345',
      },
      data: { name: 'test-group' },
    });
    
    expect(response.status()).toBe(403);
  });
});

// ============ 5. Open Redirect 测试 ============

test.describe('Open Redirect 防御', () => {
  test('OIDC 授权端点验证 redirect_uri', async ({ page }) => {
    // 尝试使用恶意 redirect_uri
    const maliciousUrls = [
      'http://evil.com/callback',
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
    ];
    
    for (const evilUrl of maliciousUrls) {
      await page.goto(`/authorize?client_id=nonexistent-client&redirect_uri=${encodeURIComponent(evilUrl)}&response_type=code&scope=openid`);
      await page.waitForTimeout(500);
      
      // 核心安全验证：服务器不应执行重定向到恶意 URL
      const url = page.url();
      
      // 验证没有发生实际重定向 - URL 应该仍在 localhost:3000
      expect(url.startsWith('http://localhost:3000')).toBe(true);
      
      // 验证没有被重定向到恶意域（检查 URL 主机部分，而非查询参数）
      const urlObj = new URL(url);
      expect(urlObj.host).not.toBe('evil.com');
      expect(urlObj.protocol).not.toBe('javascript:');
      expect(urlObj.protocol).not.toBe('data:');
    }
  });

  test('登录后重定向验证', async ({ page }) => {
    // 尝试通过 next 参数进行开放重定向攻击
    const maliciousRedirects = [
      'http://evil.com/phish',
      '//evil.com',
      'javascript:alert(document.cookie)',
    ];
    
    for (const evilRedirect of maliciousRedirects) {
      // 直接访问带有恶意重定向的 URL
      await page.goto(`/?next=${encodeURIComponent(evilRedirect)}#login`);
      await page.waitForTimeout(300);
      
      // 核心安全验证：验证当前 URL 仍在 localhost
      const url = page.url();
      const urlObj = new URL(url);
      
      // 验证 URL 仍在 localhost（没有被重定向到恶意域）
      expect(urlObj.host).toBe('localhost:3000');
      expect(urlObj.protocol).toBe('http:');
    }
  });
});

// ============ 6. 敏感信息泄露测试 ============

test.describe('敏感信息泄露防护', () => {
  test('API 错误响应不泄露敏感信息', async ({ request }) => {
    const errorTests = [
      { url: '/api/admin/users', desc: '未授权访问' },
      { url: '/api/user/me', desc: '无token访问' },
    ];
    
    for (const test of errorTests) {
      const response = await request.get(test.url);
      
      if (response.status() >= 400) {
        const body = await response.text();
        const lowerBody = body.toLowerCase();
        expect(lowerBody).not.toContain('password');
        expect(lowerBody).not.toContain('secret');
        expect(lowerBody).not.toContain('private_key');
        expect(lowerBody).not.toContain('stack trace');
      }
    }
  });

  test('用户列表不返回敏感字段', async ({ adminPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    const testData = getTestData();
    
    const response = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${testData?.adminSession}` },
    });
    
    expect(response.status()).toBe(200);
    const data = await response.json();
    
    const users = data.users || [];
    for (const user of users) {
      expect(user.password).toBeUndefined();
      expect(user.passwordHash).toBeUndefined();
      expect(user.totpSecret).toBeUndefined();
    }
  });

  test('调试端点不可访问', async ({ request }) => {
    const debugEndpoints = [
      '/debug',
      '/debug/pprof',
      '/metrics',
      '/.env',
      '/config',
    ];
    
    for (const endpoint of debugEndpoints) {
      const response = await request.get(endpoint);
      expect([401, 403, 404]).toContain(response.status());
    }
  });
});

// ============ 7. 认证绕过尝试 ============

test.describe('认证绕过防御', () => {
  test('空 Authorization header 被拒绝', async ({ request }) => {
    const response = await request.get('/api/user/me', {
      headers: { 'Authorization': '' },
    });
    expect(response.status()).toBe(401);
  });

  test('无效的 Authorization 格式被拒绝', async ({ request }) => {
    const invalidAuths = ['Bearer', 'Bearer ', 'Basic invalid', 'InvalidScheme token'];
    
    for (const auth of invalidAuths) {
      const response = await request.get('/api/user/me', {
        headers: { 'Authorization': auth },
      });
      expect(response.status()).toBe(401);
    }
  });

  test('尝试绕过认证的 HTTP 方法', async ({ request }) => {
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
    
    for (const method of methods) {
      const response = await request.fetch('/api/admin/users', {
        method,
        headers: { 'Content-Type': 'application/json' },
        data: method !== 'GET' ? {} : undefined,
      });
      
      expect([401, 403, 404, 405]).toContain(response.status());
    }
  });
});

// ============ 8. 授权绕过尝试 ============

test.describe('授权绕过防御', () => {
  test('尝试通过 HTTP 头注入绕过', async ({ request }) => {
    const response = await request.get('/api/admin/users', {
      headers: {
        'X-Forwarded-For': '127.0.0.1',
        'X-Real-IP': '127.0.0.1',
        'X-Original-URL': '/api/public/config',
      },
    });
    
    expect(response.status()).toBe(401);
  });

  test('尝试访问内部 API 端点', async ({ request }) => {
    const internalEndpoints = [
      '/internal/users',
      '/_internal/config',
      '/api/internal/users',
    ];
    
    for (const endpoint of internalEndpoints) {
      const response = await request.get(endpoint);
      expect([401, 403, 404]).toContain(response.status());
    }
  });
});

// ============ 9. 批量操作攻击测试 ============

test.describe('批量操作攻击防御', () => {
  // 限流测试已在 zz-security-brute-force.spec.ts 中专门测试
  test.skip('大量并发请求被限流', async () => {
    // 跳过：已有专门的暴力破解/限流测试文件
  });
});

// ============ 10. 路径遍历尝试 ============

test.describe('路径遍历防御', () => {
  test('尝试路径遍历获取敏感文件', async ({ request }) => {
    const traversalPayloads = [
      '/../../../etc/passwd',
      '/..%2f..%2f..%2fetc/passwd',
      '/static/../../../etc/passwd',
    ];
    
    for (const payload of traversalPayloads) {
      const response = await request.get(payload);
      
      if (response.status() === 200) {
        const body = await response.text();
        expect(body).not.toContain('root:');
        expect(body).not.toContain('/bin/bash');
      }
    }
  });

  test('API 路径遍历防护', async ({ request }) => {
    const apiTraversals = [
      '/api/users/../../../admin/users',
      '/api/public/../../../admin/users',
    ];
    
    for (const path of apiTraversals) {
      const response = await request.get(path);
      expect([401, 403, 404]).toContain(response.status());
    }
  });
});

// ============ 清理测试数据 ============

test.describe('清理', () => {
  test('清理所有测试数据', async ({ request }) => {
    const testData = getTestData();
    
    if (testData?.adminSession && testData?.testGroupId) {
      await request.delete(`/api/admin/groups/${testData.testGroupId}`, {
        headers: {
          'Cookie': `session=${testData.adminSession}`,
          'X-CSRF-Token': testData.adminCsrf || '',
        },
      }).catch(() => {});
    }
    
    if (existsSync(TEST_DATA_FILE)) {
      unlinkSync(TEST_DATA_FILE);
    }
    
    expect(true).toBeTruthy();
  });
});
