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
};
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
};

const rbac = require('rbac');
const MySQLStorage = rbac.MySQL;
MySQLStorage.prototype._convertToInstance = function (record) {
  if (!record) {
    throw new Error('Record is undefined');
  }

  if (record.is_role) {
    const instance = this.rbac.createRole(record.name, false, () => {});
    if (instance.is_nick) {
      instance.is_nick = record.is_nick;
    }
    return instance;
  } else {
    const decoded = rbac.Permission.decodeName(record.name);
    if (!decoded) {
      throw new Error('Bad permission name');
    }

    return this.rbac.createPermission(decoded.action, decoded.resource, false, () => {});
  }

  throw new Error('Type is undefined');
};


module.exports = {
  RBAC: RBAC,
  MySQLStorage: MySQLStorage,
  ensureRoleExists: function ensureRoleExists(rbac, roleName) {
    return new Promise(function (resolve, reject) {
      rbac.get(roleName, function(err, role) {
        if (role) {
          resolve(role);
        } else {
          rbac.createRole(roleName, true, function (err2, role2) {
            if(err2) {
              reject(err2);
            } else {
              resolve(role2);
            }
          });
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
