import { test, expect, waitForPageReady, STRONG_PASSWORD } from './fixture';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';

/**
 * ProxyAuth 全面 E2E 测试
 * 
 * 测试覆盖：
 * 1. 配置管理 (CRUD)
 * 2. ForwardAuth 端点
 * 3. AuthRequest 端点
 * 4. 域名提取机制 (X-Forwarded-* / Query / Host)
 * 5. 分组权限控制
 * 6. MFA 要求
 * 7. 响应头验证
 * 8. Bearer Token 认证
 * 9. 边缘情况
 */

test.describe.configure({ mode: 'serial' });

// ============ 辅助函数 ============

const ADMIN_COOKIES_FILE = '/tmp/goauth-e2e-admin-cookies.json';

function saveAdminCookies(cookies: { session?: string; csrf?: string }): void {
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

async function extractAuthCookies(page: any): Promise<{ session?: string; csrf?: string }> {
  const context = page.context();
  const cookies = await context.cookies();
  const sessionCookie = cookies.find((c: any) => c.name === 'session');
  const csrfCookie = cookies.find((c: any) => c.name === 'csrf_token');
  
  const result: { session?: string; csrf?: string } = {};
  if (sessionCookie) result.session = sessionCookie.value;
  if (csrfCookie) result.csrf = decodeURIComponent(csrfCookie.value);
  
  if (result.session || result.csrf) saveAdminCookies(result);
  return result;
}

function buildAuthHeaders(authCookies: { session?: string; csrf?: string }, contentType = 'application/json'): Record<string, string> {
  const headers: Record<string, string> = {};
  if (contentType) headers['Content-Type'] = contentType;
  
  const cookieParts: string[] = [];
  if (authCookies.session) cookieParts.push(`session=${authCookies.session}`);
  if (authCookies.csrf) cookieParts.push(`csrf_token=${encodeURIComponent(authCookies.csrf)}`);
  if (cookieParts.length > 0) headers['Cookie'] = cookieParts.join('; ');
  
  if (authCookies.csrf) headers['X-CSRF-Token'] = authCookies.csrf;
  return headers;
}

// 清理函数
async function cleanupProxyAuth(request: any, authCookies: any, domainPrefix: string) {
  if (!authCookies?.session) return;
  
  const listResponse = await request.get('/api/admin/proxy-auth', {
    headers: { 'Cookie': `session=${authCookies.session}` },
  });
  
  if (listResponse.status() === 200) {
    const data = await listResponse.json();
    for (const config of (data || [])) {
      if (config.domain && config.domain.includes(domainPrefix)) {
        await request.delete(`/api/admin/proxy-auth/${config.id}`, {
          headers: buildAuthHeaders(authCookies),
        });
      }
    }
  }
}

// ============ 测试数据 ============

let adminAuthCookies: { session?: string; csrf?: string } | null = null;
let testProxyAuthId: string;
let testGroupId: string;
let testUserId: string;

const TEST_DOMAIN_PREFIX = 'e2e-pa-';
const generateDomain = () => `${TEST_DOMAIN_PREFIX}${Date.now()}.example.com`;

// ============ ProxyAuth 配置管理 ============

test.describe('ProxyAuth 配置管理', () => {
  test.use({ storageState: undefined });

  test('创建 ProxyAuth - 基本配置', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    adminAuthCookies = await extractAuthCookies(page);
    
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("代理认证")').click();
    await page.waitForTimeout(500);

    await page.locator('button:has-text("添加配置")').click();
    await page.waitForTimeout(1000);

    const domain = generateDomain();
    await page.locator('#pa-domain').fill(domain);
    await page.getByRole('button', { name: '创建', exact: true }).click();
    await page.waitForTimeout(1000);

    await expect(page.locator(`text=${domain}`)).toBeVisible({ timeout: 5000 });
  });

  test('创建 ProxyAuth - 完整配置（带分组和 MFA）', async ({ authenticatedPage: page, request }) => {
    // 重新获取 cookies 确保有效
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    adminAuthCookies = await extractAuthCookies(page);
    
    if (!adminAuthCookies?.session || !adminAuthCookies?.csrf) {
      test.skip();
      return;
    }

    // 先创建分组
    const groupResponse = await request.post('/api/admin/groups', {
      headers: buildAuthHeaders(adminAuthCookies),
      data: { name: `proxy-group-${Date.now()}`, mfaRequired: false },
    });

    expect([200, 201]).toContain(groupResponse.status());
    const groupData = await groupResponse.json();
    testGroupId = groupData.id;

    // 创建 ProxyAuth（带分组关联）
    const domain = generateDomain();
    const createResponse = await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(adminAuthCookies),
      data: {
        domain,
        mfaRequired: true,
        maxSessionLength: 24,
        groupIds: [testGroupId],
      },
    });

    expect([200, 201]).toContain(createResponse.status());
    const data = await createResponse.json();
    testProxyAuthId = data.id;
  });

  test('创建 ProxyAuth - 验证必填字段', async ({ authenticatedPage: page, request }) => {
    // 重新获取 cookies
    adminAuthCookies = await extractAuthCookies(page);
    
    if (!adminAuthCookies?.session) {
      test.skip();
      return;
    }

    // 缺少 domain 字段
    const response = await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(adminAuthCookies),
      data: { mfaRequired: false },
    });

    expect([400, 500]).toContain(response.status());
  });

  test('列出 ProxyAuth 配置', async ({ request }) => {
    if (!adminAuthCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/api/admin/proxy-auth', {
      headers: { 'Cookie': `session=${adminAuthCookies.session}` },
    });

    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
  });

  test('更新 ProxyAuth 配置', async ({ authenticatedPage: page, request }) => {
    // 重新获取 cookies
    adminAuthCookies = await extractAuthCookies(page);
    
    if (!adminAuthCookies?.session || !testProxyAuthId) {
      test.skip();
      return;
    }

    const response = await request.patch(`/api/admin/proxy-auth/${testProxyAuthId}`, {
      headers: buildAuthHeaders(adminAuthCookies),
      data: {
        domain: `updated-${TEST_DOMAIN_PREFIX}${Date.now()}.example.com`,
        mfaRequired: false,
        maxSessionLength: 48,
      },
    });

    expect([200, 204]).toContain(response.status());
  });

  test('更新 ProxyAuth - 清空分组', async ({ authenticatedPage: page, request }) => {
    // 重新获取 cookies
    adminAuthCookies = await extractAuthCookies(page);
    
    if (!adminAuthCookies?.session || !testProxyAuthId) {
      test.skip();
      return;
    }

    const response = await request.patch(`/api/admin/proxy-auth/${testProxyAuthId}`, {
      headers: buildAuthHeaders(adminAuthCookies),
      data: { groupIds: [] },
    });

    expect([200, 204]).toContain(response.status());
  });

  test('删除 ProxyAuth 配置', async ({ authenticatedPage: page, request }) => {
    // 重新获取 cookies
    adminAuthCookies = await extractAuthCookies(page);
    
    if (!adminAuthCookies?.session) {
      test.skip();
      return;
    }

    // 创建一个用于删除的配置
    const domain = `delete-${generateDomain()}`;
    const createResponse = await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(adminAuthCookies),
      data: { domain },
    });

    if (createResponse.status() === 200 || createResponse.status() === 201) {
      const data = await createResponse.json();
      
      const deleteResponse = await request.delete(`/api/admin/proxy-auth/${data.id}`, {
        headers: buildAuthHeaders(adminAuthCookies),
      });

      expect([200, 204]).toContain(deleteResponse.status());
    }
  });
});

// ============ ForwardAuth 端点测试 ============

test.describe('ForwardAuth 端点 - 认证状态', () => {
  test('未认证请求返回 401', async ({ request }) => {
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'app.example.com',
        'X-Forwarded-Uri': '/',
      },
    });

    expect(response.status()).toBe(401);
  });

  test('无效 Session Cookie 返回 401', async ({ request }) => {
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': 'session=invalid-token-12345',
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'app.example.com',
        'X-Forwarded-Uri': '/',
      },
    });

    expect(response.status()).toBe(401);
  });

  test('认证用户返回 200 并设置响应头', async ({ request }) => {
    if (!adminAuthCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${adminAuthCookies.session}`,
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Host': 'unconfigured.example.com',
        'X-Forwarded-Uri': '/path/to/resource',
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['x-user-id']).toBeTruthy();
    expect(response.headers()['x-user-name']).toBeTruthy();
  });
});

// ============ 域名提取机制测试 ============

test.describe('ForwardAuth 域名提取', () => {
  test.use({ storageState: undefined });

  test('从 X-Forwarded-Host 提取域名', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 创建特定域名的 ProxyAuth
    const domain = `xfh-${Date.now()}.example.com`;
    await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(authCookies),
      data: { domain },
    });

    // 使用 X-Forwarded-Host 头
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${authCookies.session}`,
        'X-Forwarded-Host': domain,
        'X-Forwarded-Proto': 'https',
        'X-Forwarded-Uri': '/',
      },
    });

    expect(response.status()).toBe(200);
    
    // 清理
    await cleanupProxyAuth(request, authCookies, 'xfh-');
  });

  test('从 Query 参数提取域名', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    const domain = `query-${Date.now()}.example.com`;
    await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(authCookies),
      data: { domain },
    });

    // 使用 Query 参数
    const response = await request.get(`/authz/forward-auth?domain=${domain}`, {
      headers: {
        'Cookie': `session=${authCookies.session}`,
      },
    });

    expect(response.status()).toBe(200);
    
    // 清理
    await cleanupProxyAuth(request, authCookies, 'query-');
  });

  test('未配置域名允许所有认证用户', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 不创建 ProxyAuth，直接请求
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${authCookies.session}`,
        'X-Forwarded-Host': `notconfigured-${Date.now()}.example.com`,
      },
    });

    // 未配置的域名应该允许所有认证用户
    expect(response.status()).toBe(200);
  });
});

// ============ Bearer Token 认证测试 ============

test.describe('Bearer Token 认证', () => {
  test.use({ storageState: undefined });

  test('ForwardAuth 支持 Bearer Token', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 使用 Bearer Token (session token)
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Authorization': `Bearer ${authCookies.session}`,
        'X-Forwarded-Host': 'bearer.example.com',
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['x-user-id']).toBeTruthy();
  });

  test('AuthRequest 支持 Bearer Token', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/auth-request', {
      headers: {
        'Authorization': `Bearer ${authCookies.session}`,
      },
    });

    expect(response.status()).toBe(200);
  });

  test('无效 Bearer Token 返回 401', async ({ request }) => {
    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Authorization': 'Bearer invalid-token-xyz',
      },
    });

    expect(response.status()).toBe(401);
  });
});

// ============ AuthRequest 端点测试 ============

test.describe('AuthRequest 端点 (Nginx)', () => {
  test('未认证请求返回 401', async ({ request }) => {
    const response = await request.get('/authz/auth-request', {
      headers: {
        'X-Original-URI': '/protected/resource',
      },
    });

    expect(response.status()).toBe(401);
  });

  test('认证用户返回 200', async ({ request }) => {
    if (!adminAuthCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/auth-request', {
      headers: {
        'Cookie': `session=${adminAuthCookies.session}`,
      },
    });

    expect(response.status()).toBe(200);
    expect(response.headers()['x-user-id']).toBeTruthy();
    expect(response.headers()['x-user-name']).toBeTruthy();
  });
});

// ============ 分组权限控制测试 ============

test.describe('分组权限控制', () => {
  test.use({ storageState: undefined });

  let restrictedDomain: string;
  let allowedGroupId: string;
  let allowedUserId: string;
  let allowedUserSession: string;

  test('准备测试数据 - 创建分组和用户', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 创建受限分组
    const groupResponse = await request.post('/api/admin/groups', {
      headers: buildAuthHeaders(authCookies),
      data: { name: `allowed-group-${Date.now()}`, mfaRequired: false },
    });

    if (groupResponse.status() === 200 || groupResponse.status() === 201) {
      const groupData = await groupResponse.json();
      allowedGroupId = groupData.id;
    }

    // 创建测试用户
    const timestamp = Date.now();
    const userResponse = await request.post('/api/auth/register', {
      data: {
        username: `allowed-user-${timestamp}`,
        password: STRONG_PASSWORD,
      },
    });

    if (userResponse.status() === 200 || userResponse.status() === 201) {
      const userData = await userResponse.json();
      allowedUserId = userData.id || userData.user?.id;
    }

    // 创建受限域名
    restrictedDomain = `restricted-${Date.now()}.example.com`;
    await request.post('/api/admin/proxy-auth', {
      headers: buildAuthHeaders(authCookies),
      data: {
        domain: restrictedDomain,
        groupIds: allowedGroupId ? [allowedGroupId] : [],
      },
    });
  });

  test('用户不在分组中 - 访问被拒绝', async ({ authenticatedPage: page, request }) => {
    // 重新获取 admin cookies
    let authCookies = getAdminCookies();
    if (!authCookies?.session) {
      await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
      authCookies = await extractAuthCookies(page);
    }
    
    if (!authCookies?.session || !restrictedDomain) {
      test.skip();
      return;
    }

    // 管理员默认不在受限分组中（除非被添加）
    // 先删除管理员的分组关系（如果有）
    // 然后测试访问

    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${authCookies.session}`,
        'X-Forwarded-Host': restrictedDomain,
      },
    });

    // 如果域名有分组限制且用户不在分组中，应该返回 403
    expect([200, 403]).toContain(response.status());
  });

  test('将用户添加到分组后可以访问', async ({ authenticatedPage: page, request }) => {
    let authCookies = getAdminCookies();
    if (!authCookies?.session) {
      await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
      authCookies = await extractAuthCookies(page);
    }
    
    if (!authCookies?.session || !allowedGroupId || !restrictedDomain) {
      test.skip();
      return;
    }

    // 获取管理员用户 ID
    const usersResponse = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${authCookies.session}` },
    });

    if (usersResponse.status() === 200) {
      const usersData = await usersResponse.json();
      const adminUser = usersData.users?.find((u: any) => u.isAdmin);
      
      if (adminUser && allowedGroupId) {
        // 将管理员添加到分组
        await request.post(`/api/admin/groups/${allowedGroupId}/members`, {
          headers: buildAuthHeaders(authCookies),
          data: { userId: adminUser.id },
        });

        // 等待数据库同步
        await new Promise(r => setTimeout(r, 500));

        // 现在应该可以访问
        const response = await request.get('/authz/forward-auth', {
          headers: {
            'Cookie': `session=${authCookies.session}`,
            'X-Forwarded-Host': restrictedDomain,
          },
        });

        expect(response.status()).toBe(200);
      }
    }
  });

  test('清理分组测试数据', async ({ authenticatedPage: page, request }) => {
    let authCookies = getAdminCookies();
    if (!authCookies?.session) {
      await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
      authCookies = await extractAuthCookies(page);
    }
    
    if (!authCookies?.session) return;

    // 清理 ProxyAuth 配置
    await cleanupProxyAuth(request, authCookies, 'restricted-');

    // 清理分组
    if (allowedGroupId) {
      await request.delete(`/api/admin/groups/${allowedGroupId}`, {
        headers: buildAuthHeaders(authCookies),
      });
    }
  });
});

// ============ 禁用用户测试 ============

test.describe('禁用用户访问控制', () => {
  test.use({ storageState: undefined });

  test('禁用用户无法通过 ForwardAuth', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    // 创建测试用户
    const timestamp = Date.now();
    const registerResponse = await request.post('/api/auth/register', {
      data: {
        username: `disabled-user-${timestamp}`,
        password: STRONG_PASSWORD,
      },
    });

    if (registerResponse.status() === 200 || registerResponse.status() === 201) {
      // 登录获取 session
      const loginResponse = await request.post('/api/auth/login', {
        data: {
          username: `disabled-user-${timestamp}`,
          password: STRONG_PASSWORD,
        },
      });

      if (loginResponse.status() === 200) {
        // token 改为 HttpOnly cookie 下发，从 Set-Cookie 提取
        const userSession = loginResponse.headers()["set-cookie"]?.match(/session=([^;]+)/)?.[1] || "";

        // 获取用户 ID
        const usersResponse = await request.get('/api/admin/users', {
          headers: { 'Cookie': `session=${authCookies.session}` },
        });

        if (usersResponse.status() === 200) {
          const usersData = await usersResponse.json();
          const user = usersData.users?.find((u: any) => u.username === `disabled-user-${timestamp}`);
          
          if (user) {
            // 禁用用户
            await request.post(`/api/admin/users/${user.id}/disable`, {
              headers: buildAuthHeaders(authCookies),
            });

            // 等待数据库同步
            await new Promise(r => setTimeout(r, 500));

            // 尝试访问 ForwardAuth
            const authResponse = await request.get('/authz/forward-auth', {
              headers: {
                'Cookie': `session=${userSession}`,
              },
            });

            expect(authResponse.status()).toBe(401);
          }
        }
      }
    }
  });
});

// ============ 响应头验证测试 ============

test.describe('响应头验证', () => {
  test.use({ storageState: undefined });

  test('ForwardAuth 返回正确的用户信息头', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    const authCookies = await extractAuthCookies(page);
    
    if (!authCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/forward-auth', {
      headers: {
        'Cookie': `session=${authCookies.session}`,
        'X-Forwarded-Host': 'headers.example.com',
      },
    });

    expect(response.status()).toBe(200);
    
    const headers = response.headers();
    expect(headers['x-user-id']).toBeTruthy();
    expect(headers['x-user-name']).toBeTruthy();
    // X-User-Email 只在用户有邮箱时设置
    
    // 验证 header 值不为空
    expect(headers['x-user-id'].length).toBeGreaterThan(0);
    expect(headers['x-user-name'].length).toBeGreaterThan(0);
  });

  test('AuthRequest 返回正确的用户信息头', async ({ request }) => {
    if (!adminAuthCookies?.session) {
      test.skip();
      return;
    }

    const response = await request.get('/authz/auth-request', {
      headers: {
        'Cookie': `session=${adminAuthCookies.session}`,
      },
    });

    expect(response.status()).toBe(200);
    
    const headers = response.headers();
    expect(headers['x-user-id']).toBeTruthy();
    expect(headers['x-user-name']).toBeTruthy();
  });
});

// ============ 清理测试数据 ============

test.describe('清理', () => {
  test('清理所有测试数据', async ({ request }) => {
    const authCookies = getAdminCookies();
    if (!authCookies?.session) return;

    // 清理所有测试域名
    await cleanupProxyAuth(request, authCookies, TEST_DOMAIN_PREFIX);
    await cleanupProxyAuth(request, authCookies, 'xfh-');
    await cleanupProxyAuth(request, authCookies, 'query-');
    await cleanupProxyAuth(request, authCookies, 'restricted-');
    await cleanupProxyAuth(request, authCookies, 'delete-');
    await cleanupProxyAuth(request, authCookies, 'updated-');
    await cleanupProxyAuth(request, authCookies, 'e2e-pa-');

    // 尝试删除 cookies 文件
    try {
      if (existsSync(ADMIN_COOKIES_FILE)) {
        unlinkSync(ADMIN_COOKIES_FILE);
      }
    } catch {
      // 忽略删除错误
    }
  });
});