import { test, expect, waitForPageReady, STRONG_PASSWORD, getSavedAdmin } from './fixture';

/**
 * CSRF 保护 E2E 测试
 * 
 * 测试覆盖：
 * 1. 无 CSRF Token 时 POST/DELETE 请求被拒绝
 * 2. 无效 CSRF Token 被拒绝
 * 3. CSRF Token 自动设置
 * 4. 敏感操作需要 CSRF Token
 */

test.describe.configure({ mode: 'serial' });

test.describe('CSRF Token 设置', () => {
  test.use({ storageState: undefined });

  test('登录后自动设置 CSRF Token Cookie', async ({ authenticatedPage: page, context }) => {
    // 验证已登录
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 检查 CSRF token cookie 存在
    const cookies = await context.cookies();
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    
    expect(csrfCookie).toBeDefined();
    expect(csrfCookie?.value).toBeTruthy();
  });

  test('CSRF Token 格式正确', async ({ authenticatedPage: page, context }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await context.cookies();
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    
    // CSRF token 可能被 URL 编码，解码后验证
    const decodedToken = decodeURIComponent(csrfCookie?.value || '');
    expect(decodedToken).toMatch(/^[A-Za-z0-9_-]+=*$/);
  });
});

test.describe('CSRF 保护验证', () => {
  test.use({ storageState: undefined });

  test('无 CSRF Token 的 POST 请求被拒绝', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取 session cookie
    const context = page.context();
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    
    if (!sessionCookie) {
      test.skip();
      return;
    }

    // 发送不带 CSRF token 的请求
    const response = await request.post('/api/admin/groups', {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
        'Content-Type': 'application/json',
      },
      data: { name: 'csrf-test-group' },
    });

    // 应该返回 403 Forbidden
    expect(response.status()).toBe(403);
  });

  test('无 CSRF Token 的 DELETE 请求被拒绝', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const context = page.context();
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    
    if (!sessionCookie) {
      test.skip();
      return;
    }

    // 发送不带 CSRF token 的删除请求
    const response = await request.delete('/api/admin/groups/nonexistent-id', {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
      },
    });

    // 应该返回 403 Forbidden
    expect(response.status()).toBe(403);
  });

  test('无效 CSRF Token 的请求被拒绝', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const context = page.context();
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    
    if (!sessionCookie) {
      test.skip();
      return;
    }

    // 发送带无效 CSRF token 的请求
    const response = await request.post('/api/admin/groups', {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'invalid-csrf-token-12345',
      },
      data: { name: 'csrf-test-group' },
    });

    // 应该返回 403 Forbidden
    expect(response.status()).toBe(403);
  });

  test('有效 CSRF Token 的请求被接受', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 使用页面上下文发送请求（自动携带正确的 CSRF token）
    const result = await page.evaluate(async () => {
      // 从 cookie 中获取 CSRF token
      const getCsrfToken = () => {
        const name = 'csrf_token=';
        const decodedCookie = decodeURIComponent(document.cookie);
        const ca = decodedCookie.split(';');
        for (let i = 0; i < ca.length; i++) {
          let c = ca[i];
          while (c.charAt(0) === ' ') {
            c = c.substring(1);
          }
          if (c.indexOf(name) === 0) {
            return c.substring(name.length, c.length);
          }
        }
        return '';
      };
      
      const csrfToken = getCsrfToken();
      
      const res = await fetch('/api/admin/groups', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ name: `csrf-valid-${Date.now()}` }),
      });
      
      return { status: res.status, ok: res.ok };
    });

    // 应该成功创建
    expect([200, 201]).toContain(result.status);
  });
});

test.describe('CSRF 豁免路径', () => {
  test('登录接口不需要 CSRF Token', async ({ page, request }) => {
    const savedAdmin = getSavedAdmin();
    if (!savedAdmin) {
      test.skip();
      return;
    }

    // 发送登录请求（无 CSRF token）
    const response = await request.post('/api/auth/login', {
      data: {
        username: savedAdmin.username,
        password: savedAdmin.password,
      },
    });

    // 应该成功
    expect([200, 401, 429]).toContain(response.status());
  });

  test('注册接口不需要 CSRF Token', async ({ request }) => {
    const username = `csrf_register_${Date.now()}`;
    
    // 发送注册请求（无 CSRF token）
    const response = await request.post('/api/auth/register', {
      data: {
        username,
        password: STRONG_PASSWORD,
      },
    });

    // 应该成功或返回错误（密码强度等），但不是因为 CSRF
    expect([200, 201, 400]).toContain(response.status());
  });

  test('登出接口需要 CSRF Token', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const context = page.context();
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    
    if (!sessionCookie) {
      test.skip();
      return;
    }

    // 发送登出请求（无 CSRF token）
    const response = await request.post('/api/auth/logout', {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
      },
    });

    // 缺少 CSRF token 应被拒绝
    expect(response.status()).toBe(403);
  });
});

test.describe('CSRF Token 与 Cookie 匹配', () => {
  test.use({ storageState: undefined });

  test('CSRF Token 必须与 Cookie 中的值匹配', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const context = page.context();
    const cookies = await context.cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');
    
    if (!sessionCookie || !csrfCookie) {
      test.skip();
      return;
    }

    // 使用正确的 CSRF cookie 但在 header 中使用错误的值
    const response = await request.post('/api/admin/groups', {
      headers: {
        'Cookie': `session=${sessionCookie.value}; csrf_token=${csrfCookie.value}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'wrong-token-value',
      },
      data: { name: 'csrf-mismatch-test' },
    });

    // 应该被拒绝
    expect(response.status()).toBe(403);
  });
});
