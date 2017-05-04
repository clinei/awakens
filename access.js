const RBAC = require('rbac').default;

// hacks to get around rbac library not supporting ES6 promises (yet)
RBAC.prototype.getPromise = function (name) {
    return new Promise(function (resolve, reject) {
        this.get(name, function (err, got) {
            if (err) {
                reject(err);
            } else {
                resolve(got);
            }
        });
    }.bind(this));
}
RBAC.prototype.canPromise = function (roleName, action, resource) {
    return new Promise(function (resolve, reject) {
        this.can(roleName, action, resource, function (err, can) {
            if (err) {
                reject(err);
            } else {
                resolve(can);
            }
        });
    }.bind(this));
}

module.exports = {
    RBAC: RBAC,
    ensureRoleExists: function ensureRoleExists(rbac, roleName) {
        return new Promise(function (resolve, reject) {
            rbac.existsRole(roleName, function(err, exists) {
                function sharedResolve (err2, role) {
                    if (!err2) {
                        resolve(role);
                    } else {
                        resolve();
                        reject(err2);
                    }
                }

                if (!exists) {
                    Promise.resolve(new Promise(function(resolve2, reject2) {
                        rbac.createRole(roleName, true, sharedResolve);
                    }));
                } else {
                    Promise.resolve(new Promise(function (resolve2, reject2) {
                        rbac.getRole(roleName, sharedResolve);
                    }));
                }
            });
        });
    },
    defaultRules: {
        roles: ['basic', 'mod', 'admin', 'jesus', 'god'],
        grants: {
            basic: ['send_chatMessage', 'send_pm', 'set_flair', 'set_hat', 'set_cursor', 'set_afkText', 'view_banlist', 'grant_permission', 'revoke_permission'],
            mod: ['basic'],
            admin: ['mod', 'change_background', 'kick_user'],
            jesus: ['admin', 'see_onlineUserIP', 'ban_user', 'banip_user', 'unban_user', 'whitelist_user', 'grant_user'],
            god: ['jesus', 'see_offlineUserIP', 'delete_user', 'send_globalMessage', 'refresh_view', 'give_hat', 'remove_hat']
        },
        permissions: {
            background: ['change'],
            onlineUserIP: ['see'],
            offlineUserIP: ['see'],
            chatMessage: ['send'],
            globalMessage: ['send'],
            pm: ['send'],
            user: ['kick', 'ban', 'banip', 'unban', 'whitelist', 'unwhitelist', 'delete'],
            permission: ['grant', 'revoke', 'can', 'has', 'grants', 'cans'],
            banlist: ['view'],
            flair: ['set'],
            hat: ['set', 'give', 'remove', 'list'],
            cursor: ['set', 'list'],
            afkText: ['set'],
            view: ['refresh']
        }
    }
};
