import { test, expect, waitForPageReady, STRONG_PASSWORD, registerCleanup, extractAuthCookies, buildAuthHeaders, getSavedAdmin } from './fixture';
import { writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';

/**
 * 管理后台 E2E 测试
 * 
 * 注意：此文件创建的资源会在清理阶段自动删除
 */

// 清理数据文件
const CLEANUP_DATA_FILE = '/tmp/goauth-e2e-admin-basic-cleanup.json';

interface CleanupData {
  groupIds: string[];
  clientIds: string[];
  invitationIds: string[];
  proxyAuthIds: string[];
}

function getCleanupData(): CleanupData {
  if (!existsSync(CLEANUP_DATA_FILE)) {
    return { groupIds: [], clientIds: [], invitationIds: [], proxyAuthIds: [] };
  }
  try {
    return JSON.parse(readFileSync(CLEANUP_DATA_FILE, 'utf-8'));
  } catch {
    return { groupIds: [], clientIds: [], invitationIds: [], proxyAuthIds: [] };
  }
}

function saveCleanupData(data: CleanupData): void {
  writeFileSync(CLEANUP_DATA_FILE, JSON.stringify(data));
}

function addGroupId(id: string): void {
  const data = getCleanupData();
  data.groupIds.push(id);
  saveCleanupData(data);
}

function addClientId(id: string): void {
  const data = getCleanupData();
  data.clientIds.push(id);
  saveCleanupData(data);
}

function addInvitationId(id: string): void {
  const data = getCleanupData();
  data.invitationIds.push(id);
  saveCleanupData(data);
}

function addProxyAuthId(id: string): void {
  const data = getCleanupData();
  data.proxyAuthIds.push(id);
  saveCleanupData(data);
}

test.describe.configure({ mode: 'serial' });

test.describe('管理后台', () => {
  test.use({ storageState: undefined });

  test('管理员可以访问管理后台', async ({ authenticatedPage: page }) => {
    // 验证已在管理后台
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    // 验证有管理标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await expect(tabs.locator('button:has-text("用户")')).toBeVisible();
    await expect(tabs.locator('button:has-text("分组")')).toBeVisible();
    await expect(tabs.locator('button:has-text("客户端")')).toBeVisible();
  });

  test('用户标签页显示用户列表', async ({ authenticatedPage: page }) => {
    // 确保在管理后台
    await page.goto('/#admin');
    await waitForPageReady(page);

    // 点击用户标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("用户")').click();
    await page.waitForTimeout(500);

    // 检查用户表格存在 - 使用 .first() 因为页面有多个表格
    await expect(page.locator('table').first()).toBeVisible({ timeout: 5000 });
  });
});

test.describe('分组管理', () => {
  test.use({ storageState: undefined });

  test('可以创建分组', async ({ authenticatedPage: page, request }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    // 点击分组标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("分组")').click();
    await page.waitForTimeout(500);

    // 点击新建分组按钮
    await page.locator('button:has-text("新建分组")').click();
    await page.waitForTimeout(500);

    // 填写分组名称
    const groupName = `test_group_${Date.now()}`;
    await page.locator('#group-name').fill(groupName);

    // 提交 - 使用 .first() 因为页面有多个创建按钮
    await page.locator('.modal button:has-text("创建")').first().click();
    await page.waitForTimeout(1000);

    // 验证分组创建成功 - 使用 .first() 因为可能有多个匹配
    await expect(page.locator(`text=${groupName}`).first()).toBeVisible({ timeout: 5000 });
    
    // 获取创建的分组 ID 用于清理
    const authCookies = await extractAuthCookies(page);
    const groupsResponse = await request.get('/api/admin/groups', {
      headers: buildAuthHeaders(authCookies),
    });
    if (groupsResponse.status() === 200) {
      const groups = await groupsResponse.json();
      const createdGroup = groups.find((g: any) => g.name === groupName);
      if (createdGroup) {
        addGroupId(createdGroup.id);
      }
    }
  });

  test('分组列表显示成员数量', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("分组")').click();
    await page.waitForTimeout(1000);

    // 验证分组表格存在 - 找包含"成员"表头的表格
    const table = page.locator('table').filter({ has: page.locator('th:has-text("成员")') });
    await expect(table).toBeVisible({ timeout: 5000 });

    // 验证表格中有一行数据（刚创建的分组）
    const rows = table.locator('tbody tr');
    await expect(rows.first()).toBeVisible({ timeout: 5000 });
  });

  test('可以打开分组成员管理模态框', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("分组")').click();
    await page.waitForTimeout(500);

    // 点击第一个分组的成员管理按钮
    const memberBtn = page.locator('button:has-text("成员")').first();
    await memberBtn.click();
    await page.waitForTimeout(500);

    // 验证成员管理模态框打开
    const modal = page.locator('.modal:has(h2:has-text("分组成员管理"))');
    await expect(modal).toBeVisible({ timeout: 5000 });

    // 验证成员列表区域存在
    await expect(modal.locator('.member-list')).toBeVisible({ timeout: 5000 });

    // 验证用户选择下拉框存在
    await expect(modal.locator('select.form-select')).toBeVisible({ timeout: 5000 });

    // 验证关闭按钮存在
    await expect(modal.locator('button:has-text("关闭")')).toBeVisible({ timeout: 5000 });
  });

  test('可以关闭分组成员管理模态框', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("分组")').click();
    await page.waitForTimeout(500);

    // 打开成员管理模态框
    await page.locator('button:has-text("成员")').first().click();
    await page.waitForTimeout(500);

    const modal = page.locator('.modal:has(h2:has-text("分组成员管理"))');
    await expect(modal).toBeVisible({ timeout: 5000 });

    // 点击关闭按钮
    await modal.locator('button:has-text("关闭")').click();
    await page.waitForTimeout(500);

    // 验证模态框已关闭
    await expect(modal).not.toBeVisible({ timeout: 5000 });
  });
});

test.describe('客户端管理', () => {
  test.use({ storageState: undefined });

  test('可以创建 OIDC 客户端', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    // 点击客户端标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("客户端")').click();
    await page.waitForTimeout(500);

    // 点击新建客户端按钮
    await page.locator('button:has-text("新建客户端")').click();
    await page.waitForTimeout(1000);

    // 填写客户端信息
    const clientId = `test_client_${Date.now()}`;
    await page.locator('#client-id').fill(clientId);
    await page.locator('#client-redirect').fill('http://localhost:3000/callback');

    // 等待表单更新
    await page.waitForTimeout(500);

    // 点击创建按钮 - 使用 getByRole 更精确
    await page.getByRole('button', { name: '创建' }).click();
    await page.waitForTimeout(1000);

    // 验证客户端创建成功
    await expect(page.locator(`text=${clientId}`).first()).toBeVisible({ timeout: 5000 });
    
    // 记录创建的客户端 ID 用于清理
    addClientId(clientId);
  });

  test('可以创建可信客户端', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    // 点击客户端标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("客户端")').click();
    await page.waitForTimeout(500);

    // 点击新建客户端按钮
    await page.locator('button:has-text("新建客户端")').click();
    await page.waitForTimeout(1000);

    // 填写客户端信息
    const clientId = `trusted_client_${Date.now()}`;
    await page.locator('#client-id').fill(clientId);
    await page.locator('#client-redirect').fill('http://localhost:3000/callback');

    // 勾选可信客户端 - 使用 label 文本定位
    await page.locator('label:has-text("可信客户端")').click();
    await page.waitForTimeout(500);

    // 点击创建按钮 - 使用 getByRole 更精确
    await page.getByRole('button', { name: '创建' }).click();
    await page.waitForTimeout(1000);

    // 验证创建成功
    await expect(page.locator(`text=${clientId}`).first()).toBeVisible({ timeout: 5000 });
    
    // 记录创建的客户端 ID 用于清理
    addClientId(clientId);
  });
});

test.describe('邀请管理', () => {
  test.use({ storageState: undefined });

  test('可以创建邀请链接', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    // 点击邀请标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("邀请")').click();
    await page.waitForTimeout(500);

    // 点击创建邀请按钮
    await page.locator('button:has-text("创建邀请")').click();
    await page.waitForTimeout(1000);

    // 填写邮箱
    const email = `invite_${Date.now()}@test.local`;
    await page.locator('#invite-email').fill(email);

    // 等待表单更新
    await page.waitForTimeout(500);

    // 点击创建按钮 - 使用 exact: true 精确匹配
    await page.getByRole('button', { name: '创建', exact: true }).click();
    await page.waitForTimeout(1000);

    // 验证邀请创建成功 - 检查邮箱是否出现在表格中
    await expect(page.locator(`text=${email}`)).toBeVisible({ timeout: 5000 });
  });
});

test.describe('代理认证管理', () => {
  test.use({ storageState: undefined });

  test('可以添加代理认证配置', async ({ authenticatedPage: page }) => {
    await page.goto('/#admin');
    await waitForPageReady(page);

    // 点击代理认证标签 - 使用 .tabs 容器限定范围
    const tabs = page.locator('.tabs');
    await tabs.locator('button:has-text("代理认证")').click();
    await page.waitForTimeout(500);

    // 点击添加按钮
    await page.locator('button:has-text("添加配置")').click();
    await page.waitForTimeout(1000);

    // 填写代理认证配置
    const domain = `app${Date.now()}.example.com`;
    await page.locator('#pa-domain').fill(domain);

    // 等待表单更新
    await page.waitForTimeout(500);

    // 点击创建按钮 - 使用 exact: true 精确匹配
    await page.getByRole('button', { name: '创建', exact: true }).click();
    await page.waitForTimeout(1000);

    // 验证代理认证配置已添加 - 检查域名是否出现在表格中
    await expect(page.locator(`text=${domain}`)).toBeVisible({ timeout: 5000 });
  });
});

// ============ 清理测试数据 ============

test.describe('清理', () => {
  test.use({ storageState: undefined });

  test('清理所有测试创建的资源', async ({ authenticatedPage: page, request }) => {
    await expect(page.locator('h1:has-text("管理后台")')).toBeVisible({ timeout: 5000 });
    
    const authCookies = await extractAuthCookies(page);
    const cleanupData = getCleanupData();
    
    // 清理分组
    for (const groupId of cleanupData.groupIds) {
      await request.delete(`/api/admin/groups/${groupId}`, {
        headers: buildAuthHeaders(authCookies),
      }).catch(() => {});
    }
    
    // 清理客户端
    for (const clientId of cleanupData.clientIds) {
      await request.delete(`/api/admin/clients/${clientId}`, {
        headers: buildAuthHeaders(authCookies),
      }).catch(() => {});
    }
    
    // 清理邀请
    for (const invitationId of cleanupData.invitationIds) {
      await request.delete(`/api/admin/invitations/${invitationId}`, {
        headers: buildAuthHeaders(authCookies),
      }).catch(() => {});
    }
    
    // 清理代理认证
    for (const proxyAuthId of cleanupData.proxyAuthIds) {
      await request.delete(`/api/admin/proxy-auth/${proxyAuthId}`, {
        headers: buildAuthHeaders(authCookies),
      }).catch(() => {});
    }
    
    // 清理数据文件
    try {
      if (existsSync(CLEANUP_DATA_FILE)) {
        unlinkSync(CLEANUP_DATA_FILE);
      }
    } catch {}
    
    expect(true).toBeTruthy();
  });
});