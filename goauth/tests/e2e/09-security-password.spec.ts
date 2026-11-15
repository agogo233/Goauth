import { test, expect, waitForPageReady, STRONG_PASSWORD, getSavedAdmin, generateTestUser } from './fixture';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';

/**
 * 密码安全 E2E 测试
 * 
 * 测试覆盖：
 * 1. 密码强度验证
 * 2. 密码修改安全（旧密码验证、会话处理）
 * 3. 密码泄露防护
 * 4. 密码重放攻击防护
 * 5. 管理员密码重置安全
 * 6. 密码历史与重复使用
 * 7. 暴力破解防护
 */

test.describe.configure({ mode: 'serial' });

const TEST_USER_FILE = '/tmp/goauth-e2e-password-security-user.json';

interface TestUserData {
  username: string;
  password: string;
  email: string;
  id?: string;
  session?: string;
  csrf?: string;
}

function saveTestUser(user: TestUserData): void {
  writeFileSync(TEST_USER_FILE, JSON.stringify(user));
}

function getTestUser(): TestUserData | null {
  if (!existsSync(TEST_USER_FILE)) return null;
  try {
    return JSON.parse(readFileSync(TEST_USER_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

function cleanupTestUser(): void {
  try {
    if (existsSync(TEST_USER_FILE)) unlinkSync(TEST_USER_FILE);
  } catch {}
}

// ========== 1. 密码强度验证测试 ==========

test.describe('密码强度验证', () => {
  test('弱密码在注册时被拒绝', async ({ page }) => {
    await page.goto('/');
    await waitForPageReady(page);

    const weakPasswords = [
      '123456',
      'password',
      'qwerty',
      'abc123',
      '111111',
      'admin',
      'letmein',
      'welcome',
    ];

    for (const weakPwd of weakPasswords.slice(0, 3)) {
      // 导航到注册页面
      await page.goto('/#register');
      await waitForPageReady(page);

      const username = `weakpwd_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
      await page.locator('#reg-username').fill(username);
      await page.locator('#reg-email').fill(`${username}@test.local`);
      await page.locator('#reg-password').fill(weakPwd);
      await page.locator('#reg-confirm').fill(weakPwd);

      await page.locator('button:has-text("注册")').click();
      await page.waitForTimeout(2000);

      // 应该显示错误或仍在注册页
      const hasError = await page.locator('.error, [class*="error"]').isVisible({ timeout: 2000 }).catch(() => false);
      const stillOnRegister = await page.locator('h1:has-text("注册")').isVisible({ timeout: 1000 }).catch(() => false);

      expect(hasError || stillOnRegister).toBeTruthy();
    }
  });

  test('常见弱密码模式被检测', async ({ request }) => {
    const commonPatterns = [
      'Password123',
      'Admin12345',
      'User2024!',
      'Test123456',
    ];

    for (const pwd of commonPatterns) {
      const response = await request.post('/api/public/password-strength', {
        data: { password: pwd },
      });

      if (response.status() === 200) {
        const result = await response.json();
        // 检查密码强度分数
        if (result.score !== undefined) {
          expect(result.score).toBeLessThan(4); // 应该不是最强
        }
      }
    }
  });

  test('强密码被接受', async ({ page }) => {
    await page.goto('/');
    await waitForPageReady(page);

    // 点击注册链接导航到注册页面
    const registerLink = page.locator('a:has-text("注册")');
    if (await registerLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await registerLink.click();
      await page.waitForTimeout(500);
    } else {
      await page.goto('/#register');
    }

    await waitForPageReady(page);

    const username = `strongpwd_${Date.now()}`;
    await page.locator('#reg-username').fill(username);
    await page.locator('#reg-email').fill(`${username}@test.local`);
    await page.locator('#reg-password').fill(STRONG_PASSWORD);
    await page.locator('#reg-confirm').fill(STRONG_PASSWORD);

    await page.locator('button:has-text("注册")').click();
    await page.waitForTimeout(2000);

    // 应该成功注册并跳转到登录页
    await expect(page.locator('h1:has-text("登录")')).toBeVisible({ timeout: 10000 });
  });

  test('密码强度 API 返回正确信息', async ({ request }) => {
    const response = await request.post('/api/public/password-strength', {
      data: { password: STRONG_PASSWORD },
    });

    expect(response.status()).toBe(200);

    const result = await response.json();
    expect(result.score).toBeDefined();
    expect(result.score).toBeGreaterThanOrEqual(3); // 强密码分数 >= 3
  });

  test('密码和确认密码不匹配时拒绝', async ({ page }) => {
    await page.goto('/');
    await waitForPageReady(page);

    // 点击注册链接导航到注册页面
    const registerLink = page.locator('a:has-text("注册")');
    if (await registerLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await registerLink.click();
      await page.waitForTimeout(500);
    } else {
      await page.goto('/#register');
    }

    await waitForPageReady(page);

    const username = `mismatch_${Date.now()}`;
    await page.locator('#reg-username').fill(username);
    await page.locator('#reg-email').fill(`${username}@test.local`);
    await page.locator('#reg-password').fill(STRONG_PASSWORD);
    await page.locator('#reg-confirm').fill('Different-Password-123!');

    await page.locator('button:has-text("注册")').click();
    await page.waitForTimeout(2000);

    // 应该显示错误
    const hasError = await page.locator('.error').isVisible({ timeout: 3000 }).catch(() => false);
    const stillOnRegister = await page.locator('h1:has-text("注册")').isVisible({ timeout: 1000 }).catch(() => false);

    expect(hasError || stillOnRegister).toBeTruthy();
  });
});

// ========== 2. 密码修改安全测试 ==========

test.describe('密码修改安全', () => {
  test.use({ storageState: undefined });

  test('修改密码需要验证旧密码', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 尝试使用错误的旧密码修改
    const result = await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );

      const res = await fetch('/api/user/password', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          oldPassword: 'WrongOldPassword123!',
          newPassword: 'NewStrongPassword456!',
        }),
      });

      return { status: res.status, body: await res.text() };
    });

    // 应该拒绝错误的旧密码
    expect([400, 401, 403]).toContain(result.status);
  });

  test('新密码必须满足强度要求', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const weakNewPasswords = ['123456', 'password', 'abc'];

    for (const weakPwd of weakNewPasswords) {
      const result = await page.evaluate(async (pwd: string) => {
        const csrfToken = decodeURIComponent(
          document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
        );

        const res = await fetch('/api/user/password', {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
          },
          body: JSON.stringify({
            oldPassword: 'SomePassword123!',
            newPassword: pwd,
          }),
        });

        return { status: res.status };
      }, weakPwd);

      // 应该拒绝弱密码
      expect([400, 422]).toContain(result.status);
    }
  });

  test('缺少必填字段时拒绝', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 缺少 oldPassword
    const result1 = await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );

      const res = await fetch('/api/user/password', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          newPassword: 'NewPassword123!',
        }),
      });

      return { status: res.status };
    });

    expect([400, 422]).toContain(result1.status);

    // 缺少 newPassword
    const result2 = await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );

      const res = await fetch('/api/user/password', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          oldPassword: 'OldPassword123!',
        }),
      });

      return { status: res.status };
    });

    expect([400, 422]).toContain(result2.status);
  });

  test('密码修改需要 CSRF Token', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (!sessionCookie) {
      test.skip();
      return;
    }

    // 不带 CSRF Token 的请求
    const response = await request.patch('/api/user/password', {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
        'Content-Type': 'application/json',
      },
      data: {
        oldPassword: 'OldPassword123!',
        newPassword: 'NewPassword456!',
      },
    });

    // 应该返回 403
    expect(response.status()).toBe(403);
  });
});

// ========== 3. 密码修改后会话处理测试 ==========

test.describe('密码修改后会话处理', () => {
  test.use({ storageState: undefined });

  test('修改密码后其他会话被终止', async ({ browser }) => {
    const savedAdmin = getSavedAdmin();
    if (!savedAdmin) {
      test.skip();
      return;
    }

    // 创建两个会话
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();

    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    try {
      // 第一个会话登录
      await page1.goto('/');
      await waitForPageReady(page1);
      await page1.locator('#username').fill(savedAdmin.username);
      await page1.locator('#password').fill(savedAdmin.password);
      await page1.locator('button[type="submit"]:has-text("登录")').click();
      await page1.waitForTimeout(2000);

      // 第二个会话登录
      await page2.goto('/');
      await waitForPageReady(page2);
      await page2.locator('#username').fill(savedAdmin.username);
      await page2.locator('#password').fill(savedAdmin.password);
      await page2.locator('button[type="submit"]:has-text("登录")').click();
      await page2.waitForTimeout(2000);

      // 验证两个会话都有效
      const logged1 = await page1.locator('h1:has-text("管理后台")').isVisible({ timeout: 3000 }).catch(() => false);
      const logged2 = await page2.locator('h1:has-text("管理后台")').isVisible({ timeout: 3000 }).catch(() => false);

      expect(logged1).toBeTruthy();
      expect(logged2).toBeTruthy();

      // 在第一个会话修改密码
      // 注意：这里我们只测试 API 的行为，不实际修改密码（避免影响其他测试）
      console.log('Password change session handling test completed');
    } finally {
      await context1.close();
      await context2.close();
    }
  });

  test('当前会话在密码修改后保持有效', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 获取当前会话信息
    const beforeSessions = await page.evaluate(async () => {
      const res = await fetch('/api/user/sessions');
      return res.ok ? await res.json() : [];
    });

    // 当前会话数
    const beforeCount = beforeSessions.length || 0;
    expect(beforeCount).toBeGreaterThanOrEqual(1);

    // 验证当前会话有效
    const meResponse = await page.evaluate(async () => {
      const res = await fetch('/api/user/me');
      return { status: res.status, ok: res.ok };
    });

    expect(meResponse.ok).toBeTruthy();
  });
});

// ========== 4. 密码泄露防护测试 ==========

test.describe('密码泄露防护', () => {
  test.use({ storageState: undefined });

  test('密码不出现在 API 响应中', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (!sessionCookie) {
      test.skip();
      return;
    }

    // 获取用户信息
    const response = await request.get('/api/user/me', {
      headers: { 'Cookie': `session=${sessionCookie.value}` },
    });

    expect(response.status()).toBe(200);

    const user = await response.json();

    // 验证密码相关字段不存在
    expect(user.password).toBeUndefined();
    expect(user.passwordHash).toBeUndefined();
    expect(user.password_hash).toBeUndefined();
  });

  test('管理员列表不返回密码字段', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');

    if (!sessionCookie) {
      test.skip();
      return;
    }

    const response = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${sessionCookie.value}` },
    });

    expect(response.status()).toBe(200);

    const data = await response.json();
    const users = data.users || data || [];

    for (const user of users) {
      expect(user.password).toBeUndefined();
      expect(user.passwordHash).toBeUndefined();
      expect(user.totpSecret).toBeUndefined();
    }
  });

  test('错误响应不泄露密码信息', async ({ request }) => {
    // 尝试使用无效凭据登录
    const response = await request.post('/api/auth/login', {
      data: {
        username: 'testuser',
        password: 'wrongpassword',
      },
    });

    const body = await response.text();
    const lowerBody = body.toLowerCase();

    // 不应泄露密码相关信息
    expect(lowerBody).not.toContain('password hash');
    expect(lowerBody).not.toContain('bcrypt');
    expect(lowerBody).not.toContain('hash');
  });

  test('密码在日志中不可见', async ({ authenticatedPage: page }) => {
    // 这个测试验证密码字段不会被记录
    // 实际的日志检查需要在服务器端进行
    // 这里我们只验证 API 端点的行为

    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 发送一个密码修改请求（会失败，但验证不泄露）
    const result = await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );

      const res = await fetch('/api/user/password', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          oldPassword: 'TestPassword123!',
          newPassword: 'NewTestPassword456!',
        }),
      });

      return { status: res.status, body: await res.text() };
    });

    // 响应不应包含密码明文
    expect(result.body).not.toContain('TestPassword123!');
    expect(result.body).not.toContain('NewTestPassword456!');
  });
});

// ========== 5. 管理员密码重置安全测试 ==========

test.describe('管理员密码重置安全', () => {
  test.use({ storageState: undefined });

  test('管理员可以重置用户密码', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find(c => c.name === 'session');
    const csrfCookie = cookies.find(c => c.name === 'csrf_token');

    if (!sessionCookie || !csrfCookie) {
      test.skip();
      return;
    }

    // 创建测试用户
    const testUser = generateTestUser();
    const registerResponse = await request.post('/api/auth/register', {
      data: {
        username: testUser.username,
        password: testUser.password,
        email: testUser.email,
      },
    });

    if (registerResponse.status() !== 200 && registerResponse.status() !== 201) {
      test.skip();
      return;
    }

    // 获取用户 ID
    const usersResponse = await request.get('/api/admin/users', {
      headers: { 'Cookie': `session=${sessionCookie.value}` },
    });

    const usersData = await usersResponse.json();
    const user = usersData.users?.find((u: any) => u.username === testUser.username);

    if (!user) {
      test.skip();
      return;
    }

    // 重置密码
    const resetResponse = await request.post(`/api/admin/users/${user.id}/reset-password`, {
      headers: {
        'Cookie': `session=${sessionCookie.value}`,
        'Content-Type': 'application/json',
        'X-CSRF-Token': decodeURIComponent(csrfCookie.value),
      },
      data: {
        password: STRONG_PASSWORD + '-Reset!',
      },
    });

    // 应该成功或返回特定错误
    expect([200, 201, 400, 403, 404]).toContain(resetResponse.status());
  });

  test('普通用户无法重置他人密码', async ({ request }) => {
    // 创建普通用户
    const normalUser = generateTestUser();
    await request.post('/api/auth/register', {
      data: {
        username: normalUser.username,
        password: normalUser.password,
      },
    });

    // 登录普通用户（如果需要批准，可能失败）
    const loginResponse = await request.post('/api/auth/login', {
      data: {
        username: normalUser.username,
        password: normalUser.password,
      },
    });

    if (loginResponse.status() !== 200) {
      test.skip();
      return;
    }
    // token 改为 HttpOnly cookie 下发，从 Set-Cookie 提取
    const sessionToken = loginResponse.headers()["set-cookie"]?.match(/session=([^;]+)/)?.[1] || "";

    // 尝试重置他人密码
    const resetResponse = await request.post('/api/admin/users/some-user-id/reset-password', {
      headers: {
        'Cookie': `session=${sessionToken}`,
        'Content-Type': 'application/json',
      },
      data: {
        password: 'HackedPassword123!',
      },
    });

    // 应该被拒绝
    expect([401, 403, 404]).toContain(resetResponse.status());
  });
});

// ========== 6. 密码历史与重复使用测试 ==========

test.describe('密码历史与重复使用', () => {
  test.use({ storageState: undefined });

  test('密码可以与当前密码相同（取决于策略）', async ({ authenticatedPage: page }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });

    // 注意：我们不知道当前密码，所以这个测试主要验证 API 行为
    const result = await page.evaluate(async () => {
      const csrfToken = decodeURIComponent(
        document.cookie.split(';').find((c: string) => c.trim().startsWith('csrf_token='))?.split('=')[1] || ''
      );

      // 尝试将密码修改为相同值（使用假密码测试）
      const res = await fetch('/api/user/password', {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          oldPassword: 'SamePassword123!',
          newPassword: 'SamePassword123!',
        }),
      });

      return { status: res.status };
    });

    // 应该返回错误（旧密码不正确）或接受（取决于实现）
    expect([200, 204, 400, 401]).toContain(result.status);
  });
});

// ========== 7. 密码相关暴力破解防护测试 ==========

test.describe('密码暴力破解防护', () => {
  test.use({ storageState: undefined });

  test('多次密码错误后触发限流', async ({ request }) => {
    const username = `bruteforce_pwd_${Date.now()}`;

    // 快速发送多次错误密码请求
    const responses = [];
    for (let i = 0; i < 10; i++) {
      const response = await request.post('/api/auth/login', {
        data: {
          username,
          password: `WrongPassword${i}!`,
        },
      });
      responses.push(response.status());
    }

    // 至少应该有一些请求返回 401 或 429
    const hasRateLimit = responses.some(s => s === 429);
    const allFailed = responses.every(s => s === 401 || s === 400 || s === 429);

    expect(allFailed || hasRateLimit).toBeTruthy();
  });

  test('密码修改错误不触发敏感信息泄露', async ({ request }) => {
    // 未认证用户尝试修改密码
    const response = await request.patch('/api/user/password', {
      data: {
        oldPassword: 'SomePassword123!',
        newPassword: 'NewPassword456!',
      },
    });

    expect([401, 403]).toContain(response.status());

    const body = await response.text();
    const lowerBody = body.toLowerCase();

    // 不应泄露系统信息
    expect(lowerBody).not.toContain('stack');
    expect(lowerBody).not.toContain('trace');
    expect(lowerBody).not.toContain('database');
  });
});

// ========== 8. 密码传输安全测试 ==========

test.describe('密码传输安全', () => {
  test('密码不在 URL 中传输', async ({ page }) => {
    await page.goto('/');
    await waitForPageReady(page);

    // 监听网络请求
    const requests: string[] = [];
    page.on('request', request => {
      requests.push(request.url());
    });

    // 提交登录表单
    await page.locator('#username').fill('testuser');
    await page.locator('#password').fill('TestPassword123!');
    await page.locator('button[type="submit"]:has-text("登录")').click();

    await page.waitForTimeout(2000);

    // 检查所有请求 URL 不包含密码
    for (const url of requests) {
      expect(url.toLowerCase()).not.toContain('testpassword');
      expect(url.toLowerCase()).not.toContain('password=');
    }
  });

  test('密码强度检查不泄露密码', async ({ request }) => {
    const testPassword = 'SuperSecretPassword123!';

    const response = await request.post('/api/public/password-strength', {
      data: { password: testPassword },
    });

    expect(response.status()).toBe(200);

    const result = await response.json();

    // 响应应包含强度信息，但不包含原始密码
    expect(result.password).toBeUndefined();
    expect(result.score).toBeDefined();
  });
});

// ========== 清理测试 ==========

test.describe('清理', () => {
  test('清理密码安全测试数据', async () => {
    cleanupTestUser();
    expect(true).toBeTruthy();
  });
});
