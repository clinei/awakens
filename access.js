module.exports = {
    ensureRoleExists: function ensureRoleExists(rbac, roleName, callback) {
        rbac.existsRole(roleName, function(err, exists) {
            if (!exists) {
                rbac.createRole(roleName, true, callback);
            } else {
                rbac.getRole(roleName, callback);
            }
        });
    },
    defaultRules: {
        roles: ['basic', 'mod', 'admin', 'jesus', 'god'],
        grants: {
            basic: ['send_chatMessage', 'send_pm', 'grant_permission'],
            mod: ['basic'],
            admin: ['mod', 'change_background', 'kick_user'],
            jesus: ['admin', 'see_onlineUserIP', 'ban_user', 'banip_user', 'unban_user', 'whitelist_user', 'grant_user'],
            god: ['jesus', 'see_offlineUserIP', 'delete_user', 'send_globalMessage', 'refresh_view']
        },
        permissions: {
            background: ['change'],
            onlineUserIP: ['view'],
            offlineUserIP: ['view'],
            chatMessage: ['send'],
            globalMessage: ['send'],
            pm: ['send'],
            user: ['kick', 'ban', 'banip', 'unban', 'whitelist', 'unwhitelist', 'delete'],
            permission: ['grant', 'revoke', 'can', 'has', 'grants', 'cans'],
            banlist: ['view'],
            view: ['refresh']
        }
    }
};
