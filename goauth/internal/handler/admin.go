package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"goauth/internal/model"
	"goauth/internal/repo"
	"goauth/internal/service"
)

// AdminHandler 管理员 Handler
type AdminHandler struct {
	userService       *service.UserService
	groupService      *service.GroupService
	auditService      *service.AuditService
	invitationService *service.InvitationService
	totpService       *service.TotpService
	userRepo          *repo.UserRepo
	groupRepo         *repo.GroupRepo
	clientRepo        *repo.ClientRepo
	invitationRepo    *repo.InvitationRepo
	proxyAuthRepo     *repo.ProxyAuthRepo
}

// NewAdminHandler 创建管理员 Handler
func NewAdminHandler(
	userService *service.UserService,
	groupService *service.GroupService,
	auditService *service.AuditService,
	invitationService *service.InvitationService,
	totpService *service.TotpService,
	userRepo *repo.UserRepo,
	groupRepo *repo.GroupRepo,
	clientRepo *repo.ClientRepo,
	invitationRepo *repo.InvitationRepo,
	proxyAuthRepo *repo.ProxyAuthRepo,
) *AdminHandler {
	return &AdminHandler{
		userService:       userService,
		groupService:      groupService,
		auditService:      auditService,
		invitationService: invitationService,
		totpService:       totpService,
		userRepo:          userRepo,
		groupRepo:         groupRepo,
		clientRepo:        clientRepo,
		invitationRepo:    invitationRepo,
		proxyAuthRepo:     proxyAuthRepo,
	}
}

// --- 用户管理 ---

// ListUsers 列出用户
func (h *AdminHandler) ListUsers(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	users, count, err := h.userService.ListUsers(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
		"total": count,
	})
}

// GetUser 获取用户
func (h *AdminHandler) GetUser(c *gin.Context) {
	userID := c.Param("id")

	user, err := h.userService.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// UpdateUser 更新用户
func (h *AdminHandler) UpdateUser(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Name  *string `json:"name"`
		Email *string `json:"email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	user, err := h.userService.UpdateProfile(c.Request.Context(), userID, req.Name, req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// ApproveUser 审批用户
func (h *AdminHandler) ApproveUser(c *gin.Context) {
	userID := c.Param("id")
	actorID, _ := c.Get("userID")

	err := h.userService.ApproveUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "审批失败"})
		return
	}

	_ = h.auditService.LogUserApproved(c.Request.Context(), actorID.(string), userID, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "用户已批准"})
}

// DisableUser 禁用用户
func (h *AdminHandler) DisableUser(c *gin.Context) {
	userID := c.Param("id")
	actorID, _ := c.Get("userID")

	err := h.userService.DisableUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "禁用失败"})
		return
	}

	_ = h.auditService.LogUserDisabled(c.Request.Context(), actorID.(string), userID, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "用户已禁用"})
}

// EnableUser 启用用户
func (h *AdminHandler) EnableUser(c *gin.Context) {
	userID := c.Param("id")

	err := h.userService.EnableUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "启用失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "用户已启用"})
}

// ResetUserPassword 重置用户密码
func (h *AdminHandler) ResetUserPassword(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	err := h.userService.AdminResetPassword(c.Request.Context(), userID, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actorID, _ := c.Get("userID")
	actorIDStr, _ := actorID.(string)
	_ = h.auditService.Log(c.Request.Context(), model.AuditActionPasswordReset, &actorIDStr, &userID, nil, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"message": "密码已重置"})
}

// DeleteUser 删除用户
func (h *AdminHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	actorID, _ := c.Get("userID")

	err := h.userService.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	actorIDStr := actorID.(string)
	_ = h.auditService.Log(c.Request.Context(), model.AuditActionUserDeleted, &actorIDStr, &userID, nil, c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "用户已删除"})
}

// RemoveUserTotp 移除用户的 TOTP（管理员操作）
func (h *AdminHandler) RemoveUserTotp(c *gin.Context) {
	userID := c.Param("id")
	actorID, _ := c.Get("userID")

	// 检查用户是否存在
	user, err := h.userRepo.FindByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	// 检查用户是否启用了 TOTP
	hasTotp, err := h.totpService.IsEnabled(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "检查 TOTP 状态失败"})
		return
	}
	if !hasTotp {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户未启用二步验证"})
		return
	}

	// 移除 TOTP
	if err := h.totpService.Remove(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "移除失败"})
		return
	}

	// 记录审计日志
	actorIDStr := actorID.(string)
	details := fmt.Sprintf(`{"username": "%s"}`, user.Username)
	_ = h.auditService.Log(c.Request.Context(), "totp_removed_by_admin", &actorIDStr, &userID, &details, c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"message": "二步验证已移除"})
}

// SetAdmin 设置管理员权限
func (h *AdminHandler) SetAdmin(c *gin.Context) {
	userID := c.Param("id")

	var req struct {
		IsAdmin bool `json:"isAdmin"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	err := h.userService.SetAdmin(c.Request.Context(), userID, req.IsAdmin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "设置失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已更新"})
}

// --- 分组管理 ---

// ListGroups 列出分组
func (h *AdminHandler) ListGroups(c *gin.Context) {
	// 使用单次查询获取分组和成员数量，避免 N+1
	groups, err := h.groupRepo.ListWithMemberCount(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取分组列表失败"})
		return
	}

	c.JSON(http.StatusOK, groups)
}

// CreateGroup 创建分组
func (h *AdminHandler) CreateGroup(c *gin.Context) {
	actorID, _ := c.Get("userID")

	var req struct {
		Name        string `json:"name" binding:"required"`
		MFARequired bool   `json:"mfaRequired"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	group := &model.Group{
		Name:        req.Name,
		MFARequired: req.MFARequired,
		CreatedBy:   actorID.(string),
	}

	if err := h.groupRepo.Create(c.Request.Context(), group); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}

	c.JSON(http.StatusCreated, group)
}

// UpdateGroup 更新分组
func (h *AdminHandler) UpdateGroup(c *gin.Context) {
	groupID := c.Param("id")

	var req struct {
		Name        string `json:"name"`
		MFARequired bool   `json:"mfaRequired"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	group, err := h.groupRepo.FindByID(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "分组不存在"})
		return
	}

	if req.Name != "" {
		group.Name = req.Name
	}
	group.MFARequired = req.MFARequired

	if err := h.groupRepo.Update(c.Request.Context(), group); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, group)
}

// DeleteGroup 删除分组
func (h *AdminHandler) DeleteGroup(c *gin.Context) {
	groupID := c.Param("id")

	err := h.groupRepo.Delete(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "分组已删除"})
}

// AddGroupMember 添加分组成员
func (h *AdminHandler) AddGroupMember(c *gin.Context) {
	groupID := c.Param("id")

	var req struct {
		UserID string `json:"userId" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	err := h.groupRepo.AddUserToGroup(c.Request.Context(), req.UserID, groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "添加失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已添加"})
}

// RemoveGroupMember 移除分组成员
func (h *AdminHandler) RemoveGroupMember(c *gin.Context) {
	groupID := c.Param("id")
	userID := c.Param("userId")

	err := h.groupRepo.RemoveUserFromGroup(c.Request.Context(), userID, groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "移除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已移除"})
}

// GetGroupMembers 获取分组成员列表
func (h *AdminHandler) GetGroupMembers(c *gin.Context) {
	groupID := c.Param("id")

	userIDs, err := h.groupRepo.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取成员列表失败"})
		return
	}

	// 批量获取用户详细信息，避免 N+1
	type MemberInfo struct {
		ID       string  `json:"id"`
		Username string  `json:"username"`
		Email    *string `json:"email"`
	}

	if len(userIDs) == 0 {
		c.JSON(http.StatusOK, []MemberInfo{})
		return
	}

	users, err := h.userRepo.FindByIDs(c.Request.Context(), userIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取成员信息失败"})
		return
	}

	members := make([]MemberInfo, len(users))
	for i, user := range users {
		members[i] = MemberInfo{
			ID:       user.ID,
			Username: user.Username,
			Email:    user.Email,
		}
	}

	c.JSON(http.StatusOK, members)
}

// --- 客户端管理 ---

// ListClients 列出客户端
func (h *AdminHandler) ListClients(c *gin.Context) {
	clients, err := h.clientRepo.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取客户端列表失败"})
		return
	}

	c.JSON(http.StatusOK, clients)
}

// CreateClient 创建客户端
func (h *AdminHandler) CreateClient(c *gin.Context) {
	actorID, _ := c.Get("userID")

	var req struct {
		ID           string   `json:"id" binding:"required"`
		Secret       string   `json:"secret"`
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirectUris" binding:"required"`
		Scopes       []string `json:"scopes" binding:"required"`
		Trusted      bool     `json:"trusted"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)
	scopesJSON, _ := json.Marshal(req.Scopes)
	grantTypesJSON, _ := json.Marshal([]string{"authorization_code", "refresh_token"})
	responseTypesJSON, _ := json.Marshal([]string{"code"})

	var secret *string
	if req.Secret != "" {
		secret = &req.Secret
	}

	client := &model.Client{
		ID:            req.ID,
		Name:          req.Name,
		Secret:        secret,
		RedirectURIs:  string(redirectURIsJSON),
		Scopes:        string(scopesJSON),
		GrantTypes:    string(grantTypesJSON),
		ResponseTypes: string(responseTypesJSON),
		Trusted:       req.Trusted,
		CreatedBy:     actorID.(string),
	}

	if err := h.clientRepo.Create(c.Request.Context(), client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "客户端已创建", "id": req.ID})
}

// UpdateClient 更新客户端
func (h *AdminHandler) UpdateClient(c *gin.Context) {
	clientID := c.Param("id")

	var req struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirectUris"`
		Scopes       []string `json:"scopes"`
		Trusted      bool     `json:"trusted"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	client, err := h.clientRepo.FindByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "客户端不存在"})
		return
	}

	if req.Name != "" {
		client.Name = req.Name
	}
	if len(req.RedirectURIs) > 0 {
		redirectURIsJSON, _ := json.Marshal(req.RedirectURIs)
		client.RedirectURIs = string(redirectURIsJSON)
	}
	if len(req.Scopes) > 0 {
		scopesJSON, _ := json.Marshal(req.Scopes)
		client.Scopes = string(scopesJSON)
	}
	client.Trusted = req.Trusted

	if err := h.clientRepo.Update(c.Request.Context(), client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "客户端已更新"})
}

// DeleteClient 删除客户端
func (h *AdminHandler) DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	err := h.clientRepo.Delete(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "客户端已删除"})
}

// --- 审计日志 ---

// ListAuditLogs 列出审计日志
func (h *AdminHandler) ListAuditLogs(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	logs, err := h.auditService.List(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取审计日志失败"})
		return
	}

	c.JSON(http.StatusOK, logs)
}

// --- 邀请管理 ---

// ListInvitations 列出邀请
func (h *AdminHandler) ListInvitations(c *gin.Context) {
	invitations, err := h.invitationService.ListInvitations(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取邀请列表失败"})
		return
	}

	c.JSON(http.StatusOK, invitations)
}

// CreateInvitation 创建邀请
func (h *AdminHandler) CreateInvitation(c *gin.Context) {
	actorID, _ := c.Get("userID")

	var req struct {
		Email         string   `json:"email"`
		Username      string   `json:"username"`
		Name          string   `json:"name"`
		EmailVerified bool     `json:"emailVerified"`
		GroupIDs      []string `json:"groupIds"`
		ExpiresIn     int      `json:"expiresIn"` // 小时
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	var email *string
	if req.Email != "" {
		email = &req.Email
	}
	var username *string
	if req.Username != "" {
		username = &req.Username
	}
	var name *string
	if req.Name != "" {
		name = &req.Name
	}

	invitation, err := h.invitationService.CreateInvitation(
		c.Request.Context(),
		email, username, name,
		req.EmailVerified,
		req.GroupIDs,
		actorID.(string),
		req.ExpiresIn,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}

	c.JSON(http.StatusCreated, invitation)
}

// DeleteInvitation 删除邀请
func (h *AdminHandler) DeleteInvitation(c *gin.Context) {
	invitationID := c.Param("id")

	err := h.invitationService.DeleteInvitation(c.Request.Context(), invitationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "邀请已删除"})
}

// --- ProxyAuth 管理 ---

// ListProxyAuth 列出 ProxyAuth
func (h *AdminHandler) ListProxyAuth(c *gin.Context) {
	// 使用单次查询获取 ProxyAuth 和分组，避免 N+1
	results, err := h.proxyAuthRepo.ListWithGroups(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取列表失败"})
		return
	}

	// 转换为前端需要的格式
	type ProxyAuthWithGroups struct {
		ID               string   `json:"id"`
		Domain           string   `json:"domain"`
		MFARequired      bool     `json:"mfaRequired"`
		MaxSessionLength *int     `json:"maxSessionLength"`
		CreatedBy        string   `json:"createdBy"`
		GroupIDs         []string `json:"groupIds"`
	}

	proxyAuths := make([]ProxyAuthWithGroups, len(results))
	for i, pa := range results {
		groupIDs := []string{}
		if pa.GroupIDs != nil && *pa.GroupIDs != "" {
			// GROUP_CONCAT 返回逗号分隔的字符串
			for _, id := range strings.Split(*pa.GroupIDs, ",") {
				if id != "" {
					groupIDs = append(groupIDs, id)
				}
			}
		}
		proxyAuths[i] = ProxyAuthWithGroups{
			ID:               pa.ID,
			Domain:           pa.Domain,
			MFARequired:      pa.MFARequired,
			MaxSessionLength: pa.MaxSessionLength,
			CreatedBy:        pa.CreatedBy,
			GroupIDs:         groupIDs,
		}
	}

	c.JSON(http.StatusOK, proxyAuths)
}

// CreateProxyAuth 创建 ProxyAuth
func (h *AdminHandler) CreateProxyAuth(c *gin.Context) {
	actorID, _ := c.Get("userID")

	var req struct {
		Domain           string   `json:"domain" binding:"required"`
		MFARequired      bool     `json:"mfaRequired"`
		MaxSessionLength *int     `json:"maxSessionLength"`
		GroupIDs         []string `json:"groupIds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	proxyAuth := &model.ProxyAuth{
		Domain:           req.Domain,
		MFARequired:      req.MFARequired,
		MaxSessionLength: req.MaxSessionLength,
		CreatedBy:        actorID.(string),
	}

	if err := h.proxyAuthRepo.Create(c.Request.Context(), proxyAuth, req.GroupIDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建失败"})
		return
	}

	c.JSON(http.StatusCreated, proxyAuth)
}

// UpdateProxyAuth 更新 ProxyAuth
func (h *AdminHandler) UpdateProxyAuth(c *gin.Context) {
	proxyAuthID := c.Param("id")

	var req struct {
		Domain           string   `json:"domain"`
		MFARequired      bool     `json:"mfaRequired"`
		MaxSessionLength *int     `json:"maxSessionLength"`
		GroupIDs         []string `json:"groupIds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求"})
		return
	}

	proxyAuth, err := h.proxyAuthRepo.FindByID(c.Request.Context(), proxyAuthID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "不存在"})
		return
	}

	if req.Domain != "" {
		proxyAuth.Domain = req.Domain
	}
	proxyAuth.MFARequired = req.MFARequired
	proxyAuth.MaxSessionLength = req.MaxSessionLength

	if err := h.proxyAuthRepo.Update(c.Request.Context(), proxyAuth, req.GroupIDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, proxyAuth)
}

// DeleteProxyAuth 删除 ProxyAuth
func (h *AdminHandler) DeleteProxyAuth(c *gin.Context) {
	proxyAuthID := c.Param("id")

	err := h.proxyAuthRepo.Delete(c.Request.Context(), proxyAuthID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已删除"})
}
