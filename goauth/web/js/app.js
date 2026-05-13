function app() {
  return {
    page: 'login',
    loading: false,
    error: '',
    config: {},
    user: null,
    users: [],
    groups: [],
    clients: [],
    invitations: [],
    proxyAuths: [],
    auditLogs: [],
    adminTab: 'users',
    inviteToken: null,
    userOffset: 0,
    userLimit: 20,
    userTotal: 0,

    // Modal states
    showTotpModal: false,
    showGroupModal: false,
    showClientModal: false,
    showInviteModal: false,
    showProxyAuthModal: false,
    showGroupMembersModal: false,

    // 分组成员管理状态
    selectedGroup: null,
    groupMembers: [],
    addMemberUserId: '',

    // TOTP 相关状态
    totpSetup: null,
    totpVerifyCode: '',

    // Forms
    loginForm: {
      username: '',
      password: '',
      rememberMe: false
    },

    registerForm: {
      username: '',
      email: '',
      password: '',
      confirmPassword: '',
      inviteToken: null
    },

    totpCode: '',

    groupForm: {
      name: '',
      mfaRequired: false
    },

    clientForm: {
      id: '',
      secret: '',
      name: '',
      redirectUris: '',
      scopes: 'openid profile email',
      trusted: false
    },
    editingClientId: '',

    inviteForm: {
      email: '',
      username: '',
      name: '',
      emailVerified: false,
      groupIds: [],
      expiresIn: 72
    },

    proxyAuthForm: {
      domain: '',
      mfaRequired: false,
      maxSessionLength: null,
      groupIds: []
    },

    async init() {
      await this.loadConfig();
      this.parseRoute();
      await this.checkAuth();
      
      // 监听 hash 变化，支持浏览器前进/后退和直接导航
      window.addEventListener('hashchange', () => {
        this.parseRoute();
      });
    },

    parseRoute() {
      const path = window.location.pathname;

      const inviteMatch = path.match(/^\/invite\/(.+)$/);
      if (inviteMatch) {
        this.inviteToken = inviteMatch[1];
        this.registerForm.inviteToken = this.inviteToken;
        this.setPage('register');
        return;
      }

      const hash = window.location.hash.slice(1);
      if (hash && ['login', 'register', 'admin', 'user', 'mfa', 'mfa-setup'].includes(hash)) {
        this.page = hash;
      }
    },

    setPage(page) {
      this.page = page;
      if (page === 'login' || page === 'register' || page === 'admin' || page === 'user' || page === 'mfa' || page === 'mfa-setup') {
        history.pushState({ page }, '', `#${page}`);
      } else if (this.inviteToken && page === 'register') {
        // Keep invite URL
      } else {
        history.pushState({ page }, '', window.location.pathname);
      }
    },

    async loadConfig() {
      try {
        const res = await fetch('/api/public/config');
        if (res.ok) {
          this.config = await res.json();
          document.title = this.config.appName || 'Goauth';
        }
      } catch (e) {
        console.error('Failed to load config:', e);
      }
    },

    async checkAuth() {
      try {
        const res = await this.api('GET', '/api/user/me');
        if (res.ok) {
          this.user = await res.json();
          // 只有在登录/注册页面时才自动导航
          // 不要覆盖用户显式导航到的页面（如 #user）
          if (this.inviteToken) {
            this.setPage('user');
          } else if (this.page === 'login' || this.page === 'register') {
            // 仅当用户在登录或注册页面时才重定向
            this.setPage(this.user.isAdmin ? 'admin' : 'user');
          }
          if (this.user.isAdmin) {
            await this.loadUsers();
          }
        } else {
          // 未认证，重置用户状态并跳转到登录页
          this.user = null;
          if (!this.inviteToken) {
            this.setPage('login');
          }
        }
      } catch (e) {
        // 未认证，重置用户状态并跳转到登录页
        this.user = null;
        if (!this.inviteToken) {
          this.setPage('login');
        }
      }
    },

    async login() {
      this.error = '';
      this.loading = true;

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.loginForm)
        });

        const data = await res.json();

        if (res.ok) {
          if (data.requireTotp) {
            this.setPage('mfa');
          } else if (data.requireMfaSetup) {
            // 用户被要求 MFA 但未设置，引导到 TOTP 设置页面
            this.user = data.user;
            this.setPage('mfa-setup');
          } else {
            this.user = data.user;
            this.setPage(this.user.isAdmin ? 'admin' : 'user');
            if (this.user.isAdmin) {
              await this.loadUsers();
            }
          }
        } else {
          this.error = data.error || '登录失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async register() {
      this.error = '';

      if (this.registerForm.password !== this.registerForm.confirmPassword) {
        this.error = '两次密码不一致';
        return;
      }

      this.loading = true;

      try {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.registerForm)
        });

        const data = await res.json();

        if (res.ok) {
          this.error = '';
          if (data.requiresApproval) {
            alert('注册成功，请等待管理员审批');
          }
          this.setPage('login');
          this.inviteToken = null;
          this.registerForm.inviteToken = null;
          history.pushState({}, '', '/');
        } else {
          this.error = data.error || '注册失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async verifyTotp() {
      this.error = '';
      this.loading = true;

      try {
        const res = await fetch('/api/auth/totp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: this.totpCode })
        });

        const data = await res.json();

        if (res.ok) {
          this.user = data.user;
          this.totpCode = '';
          this.setPage(this.user.isAdmin ? 'admin' : 'user');
          if (this.user.isAdmin) {
            await this.loadUsers();
          }
        } else {
          this.error = data.error || '验证失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async logout() {
      try {
        await this.api('POST', '/api/auth/logout');
      } catch (e) {}

      this.user = null;
      this.totpSetup = null;
      this.setPage('login');
    },

    // TOTP 设置
    async setupTotp() {
      this.loading = true;
      this.error = '';

      try {
        const res = await this.api('POST', '/api/mfa-setup/totp/setup');
        const data = await res.json();

        if (res.ok) {
          this.totpSetup = data;
          this.showTotpModal = true;
        } else {
          this.error = data.error || '设置失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async verifyTotpSetup() {
      if (!this.totpVerifyCode) {
        this.error = '请输入验证码';
        return;
      }

      this.loading = true;
      this.error = '';

      try {
        const res = await this.api('POST', '/api/mfa-setup/totp/verify', {
          code: this.totpVerifyCode,
          secret: this.totpSetup?.secret,
          encryptedSecret: this.totpSetup?.encryptedSecret
        });
        const data = await res.json();

        if (res.ok && data.valid) {
          this.showTotpModal = false;
          this.totpSetup = null;
          this.totpVerifyCode = '';
          await this.checkAuth();
          // 如果在 mfa-setup 页面，设置完成后跳转
          if (this.page === 'mfa-setup') {
            this.setPage(this.user?.isAdmin ? 'admin' : 'user');
            if (this.user?.isAdmin) {
              await this.loadUsers();
            }
          }
          alert('TOTP 设置成功！');
        } else {
          this.error = data.error || '验证码无效';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async removeTotp() {
      if (!confirm('确定要移除二步验证吗？这将降低账户安全性。')) {
        return;
      }

      this.loading = true;
      try {
        const res = await this.api('DELETE', '/api/user/totp');
        if (res.ok) {
          await this.checkAuth();
          alert('TOTP 已移除');
        } else {
          const data = await res.json();
          alert(data.error || '移除失败');
        }
      } catch (e) {
        alert('网络错误');
      } finally {
        this.loading = false;
      }
    },

    // 用户管理
    async loadUsers(offset) {
      if (offset !== undefined) this.userOffset = offset;
      try {
        const res = await this.api('GET', `/api/admin/users?limit=${this.userLimit}&offset=${this.userOffset}`);
        if (res.ok) {
          const data = await res.json();
          this.users = data.users || data;
          this.userTotal = data.total || this.users.length;
        }
      } catch (e) {
        console.error('Failed to load users:', e);
      }
    },

    prevPage() {
      if (this.userOffset >= this.userLimit) {
        this.loadUsers(this.userOffset - this.userLimit);
      }
    },

    nextPage() {
      if (this.userOffset + this.userLimit < this.userTotal) {
        this.loadUsers(this.userOffset + this.userLimit);
      }
    },

    async approveUser(userId) {
      try {
        const res = await this.api('POST', `/api/admin/users/${userId}/approve`);
        if (res.ok) {
          await this.loadUsers();
        } else {
          const data = await res.json();
          alert(data.error || '审批失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    async disableUser(userId) {
      if (!confirm('确定要禁用该用户吗？')) return;
      try {
        const res = await this.api('POST', `/api/admin/users/${userId}/disable`);
        if (res.ok) {
          await this.loadUsers();
        } else {
          const data = await res.json();
          alert(data.error || '禁用失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    async enableUser(userId) {
      try {
        const res = await this.api('POST', `/api/admin/users/${userId}/enable`);
        if (res.ok) {
          await this.loadUsers();
        } else {
          const data = await res.json();
          alert(data.error || '启用失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    async deleteUser(userId) {
      if (!confirm('确定要删除该用户吗？此操作不可撤销。')) return;
      try {
        const res = await this.api('DELETE', `/api/admin/users/${userId}`);
        if (res.ok) {
          await this.loadUsers();
        } else {
          const data = await res.json();
          alert(data.error || '删除失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    async resetPassword(userId) {
      const password = prompt('请输入新密码:');
      if (!password) return;

      try {
        const res = await this.api('POST', `/api/admin/users/${userId}/reset-password`, { password });
        if (res.ok) {
          alert('密码已重置');
        } else {
          const data = await res.json();
          alert(data.error || '重置失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    // 分组管理
    async loadGroups() {
      try {
        const res = await this.api('GET', '/api/admin/groups');
        if (res.ok) {
          this.groups = await res.json();
        }
      } catch (e) {
        console.error('Failed to load groups:', e);
      }
    },

    async createGroup() {
      this.error = '';
      this.loading = true;

      try {
        const res = await this.api('POST', '/api/admin/groups', this.groupForm);
        if (res.ok) {
          this.showGroupModal = false;
          this.groupForm = { name: '', mfaRequired: false };
          await this.loadGroups();
        } else {
          const data = await res.json();
          this.error = data.error || '创建失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async deleteGroup(groupId) {
      if (!confirm('确定要删除该分组吗？')) return;

      try {
        const res = await this.api('DELETE', `/api/admin/groups/${groupId}`);
        if (res.ok) {
          await this.loadGroups();
        } else {
          const data = await res.json();
          alert(data.error || '删除失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    async openGroupMembersModal(group) {
      this.selectedGroup = group;
      this.groupMembers = [];
      this.addMemberUserId = '';
      // 确保用户列表已加载
      if (this.users.length === 0) {
        await this.loadUsers();
      }
      this.showGroupMembersModal = true;
      await this.loadGroupMembers();
    },

    async loadGroupMembers() {
      if (!this.selectedGroup) return;

      try {
        const res = await this.api('GET', `/api/admin/groups/${this.selectedGroup.id}/members`);
        if (res.ok) {
          this.groupMembers = await res.json();
          // 更新分组中的成员数量
          const idx = this.groups.findIndex(g => g.id === this.selectedGroup.id);
          if (idx !== -1) {
            this.groups[idx].memberCount = this.groupMembers.length;
          }
        }
      } catch (e) {
        console.error('Failed to load group members:', e);
      }
    },

    async addGroupMember() {
      if (!this.selectedGroup || !this.addMemberUserId) return;

      try {
        const res = await this.api('POST', `/api/admin/groups/${this.selectedGroup.id}/members`, {
          userId: this.addMemberUserId
        });
        if (res.ok) {
          this.addMemberUserId = '';
          await this.loadGroupMembers();
        } else {
          const data = await res.json();
          alert(data.error || '添加失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    async removeGroupMember(userId) {
      if (!this.selectedGroup) return;
      if (!confirm('确定要将该用户从分组中移除吗？')) return;

      try {
        const res = await this.api('DELETE', `/api/admin/groups/${this.selectedGroup.id}/members/${userId}`);
        if (res.ok) {
          await this.loadGroupMembers();
        } else {
          const data = await res.json();
          alert(data.error || '移除失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    // 客户端管理
    async loadClients() {
      try {
        const res = await this.api('GET', '/api/admin/clients');
        if (res.ok) {
          this.clients = await res.json();
        }
      } catch (e) {
        console.error('Failed to load clients:', e);
      }
    },

    openNewClientModal() {
      this.editingClientId = '';
      this.clientForm = { id: '', secret: '', name: '', redirectUris: '', scopes: 'openid profile email', trusted: false };
      this.error = '';
      this.showClientModal = true;
    },

    openEditClientModal(client) {
      this.editingClientId = client.id;
      this.clientForm = {
        id: client.id,
        secret: '',
        name: client.name || '',
        redirectUris: (client.redirectUris || []).join('\n'),
        scopes: (client.scopes || []).join(', '),
        trusted: client.trusted
      };
      this.error = '';
      this.showClientModal = true;
    },

    async saveClient() {
      this.error = '';
      this.loading = true;

      try {
        const redirectUris = this.clientForm.redirectUris.split('\n').map(u => u.trim()).filter(u => u);
        const scopes = this.clientForm.scopes.split(',').map(s => s.trim()).filter(s => s);

        const body = {
          name: this.clientForm.name,
          redirectUris,
          scopes,
          trusted: this.clientForm.trusted
        };

        if (this.editingClientId) {
          const res = await this.api('PATCH', `/api/admin/clients/${this.editingClientId}`, body);
          if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || '更新失败');
          }
        } else {
          body.id = this.clientForm.id;
          body.secret = this.clientForm.secret || undefined;
          const res = await this.api('POST', '/api/admin/clients', body);
          if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || '创建失败');
          }
        }

        this.showClientModal = false;
        this.clientForm = { id: '', secret: '', name: '', redirectUris: '', scopes: 'openid profile email', trusted: false };
        this.editingClientId = '';
        await this.loadClients();
      } catch (e) {
        this.error = e.message;
      } finally {
        this.loading = false;
      }
    },

    async deleteClient(clientId) {
      if (!confirm('确定要删除该客户端吗？')) return;

      try {
        const res = await this.api('DELETE', `/api/admin/clients/${clientId}`);
        if (res.ok) {
          await this.loadClients();
        } else {
          const data = await res.json();
          alert(data.error || '删除失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    // 邀请管理
    async loadInvitations() {
      try {
        const res = await this.api('GET', '/api/admin/invitations');
        if (res.ok) {
          this.invitations = await res.json();
        }
      } catch (e) {
        console.error('Failed to load invitations:', e);
      }
    },

    async createInvitation() {
      this.error = '';
      this.loading = true;

      try {
        const res = await this.api('POST', '/api/admin/invitations', this.inviteForm);
        if (res.ok) {
          const invitation = await res.json();
          this.showInviteModal = false;
          this.inviteForm = { email: '', username: '', name: '', emailVerified: false, groupIds: [], expiresIn: 72 };
          await this.loadInvitations();
          // 显示邀请链接
          const link = `${window.location.origin}/invite/${invitation.id}`;
          prompt('邀请链接已创建：', link);
        } else {
          const data = await res.json();
          this.error = data.error || '创建失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async deleteInvitation(invitationId) {
      if (!confirm('确定要删除该邀请吗？')) return;

      try {
        const res = await this.api('DELETE', `/api/admin/invitations/${invitationId}`);
        if (res.ok) {
          await this.loadInvitations();
        } else {
          const data = await res.json();
          alert(data.error || '删除失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    copyInviteLink(invitationId) {
      const link = `${window.location.origin}/invite/${invitationId}`;
      navigator.clipboard.writeText(link).then(() => {
        alert('邀请链接已复制到剪贴板');
      }).catch(() => {
        prompt('邀请链接：', link);
      });
    },

    // ProxyAuth 管理
    async loadProxyAuths() {
      try {
        const res = await this.api('GET', '/api/admin/proxy-auth');
        if (res.ok) {
          this.proxyAuths = await res.json();
        }
      } catch (e) {
        console.error('Failed to load proxy-auth:', e);
      }
    },

    async createProxyAuth() {
      this.error = '';
      this.loading = true;

      try {
        const res = await this.api('POST', '/api/admin/proxy-auth', this.proxyAuthForm);
        if (res.ok) {
          this.showProxyAuthModal = false;
          this.proxyAuthForm = { domain: '', mfaRequired: false, maxSessionLength: null, groupIds: [] };
          await this.loadProxyAuths();
        } else {
          const data = await res.json();
          this.error = data.error || '创建失败';
        }
      } catch (e) {
        this.error = '网络错误';
      } finally {
        this.loading = false;
      }
    },

    async deleteProxyAuth(proxyAuthId) {
      if (!confirm('确定要删除该代理认证配置吗？')) return;

      try {
        const res = await this.api('DELETE', `/api/admin/proxy-auth/${proxyAuthId}`);
        if (res.ok) {
          await this.loadProxyAuths();
        } else {
          const data = await res.json();
          alert(data.error || '删除失败');
        }
      } catch (e) {
        alert('网络错误');
      }
    },

    // 审计日志
    async loadAuditLogs() {
      try {
        const res = await this.api('GET', '/api/admin/audit-logs?limit=50');
        if (res.ok) {
          this.auditLogs = await res.json();
        }
      } catch (e) {
        console.error('Failed to load audit logs:', e);
      }
    },

    // 辅助方法
    formatDate(dateStr) {
      if (!dateStr) return '-';
      const date = new Date(dateStr);
      return date.toLocaleString('zh-CN');
    },

    // 从 cookie 中获取 CSRF token
    getCsrfToken() {
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
    },

    async api(method, path, body = null) {
      const options = {
        method,
        headers: {
          'Content-Type': 'application/json'
        }
      };

      // 对于状态改变方法，添加 CSRF token
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
        const csrfToken = this.getCsrfToken();
        if (csrfToken) {
          options.headers['X-CSRF-Token'] = csrfToken;
        }
      }

      if (body) {
        options.body = JSON.stringify(body);
      }

      return fetch(path, options);
    }
  };
}

// 监听浏览器前进/后退
window.addEventListener('popstate', (event) => {
  if (event.state && event.state.page) {
    const appEl = document.querySelector('[x-data]');
    if (appEl && appEl.__x) {
      appEl.__x.$data.page = event.state.page;
    }
  }
});



