var dao = require('./dao');
var request = require('request');
var throttle = require('./throttle');
var _ = require('underscore');
var $ = require('jquery-deferred');
var express = require('express');
var fs = require('fs');
var RBAC = require('rbac').default;
var access = require('./access');
var async = require('async');

var channels = {};
var tokens = {};

function handleException(err) {
    // handle the error safely and verbosely
    console.log(err.stack);
}
process.on('uncaughtException', handleException);

function findIndex(channel, att, value) {
    var i;
    for (i = 0; i < channel.length; i++) {
        if (channel[i][att] && value) {
            if (channel[i][att].toLowerCase() === value.toLowerCase()) {
                return i;
            }
        }
    }
    return -1;
}

function findUserByAttribute(userList, att, value) {
    if (value) {
        for (var i = 0; i < userList.length; i++) {
            var user = userList[i];
            if (user[att] && value) {
                if (user[att].toLowerCase() === value.toLowerCase()) {
                    return user;
                }
            }
        }
    }
    return null;
}

function createChannel(io, channelName) {
    
    console.log('Starting channel', channelName);
    
    var room = io.of(channelName);
    
    var channel = {
        online : [],
        status : 'public',
        blockProxy : false,
        messageCount : 0
    };

    var rbac = new RBAC(access);
    var role_basic;
    rbac.get('basic', function(err, role) {
        role_basic = role;
    });
    
    function updateUserData(user, newData) {
        var roles = ['God', 'Channel Owner', 'Admin', 'Mod', 'Basic'];
        
        if (newData.nick) {
            user.nick = newData.nick;
            roomEmit('nick', user.id, user.nick);
        }
        
        if (newData.token) {
            tokens[user.nick] = newData.token;
        }
        
        if (newData.role !== undefined) {
            user.role = newData.role;
            newData.role = roles[newData.role];
        }

        if (newData.hasOwnProperty('role2')) {
            user.role2 = newData.role2;
        }
        
        if (newData.remote_addr) {//if true save current ip to database
            dao.setUserinfo(user.nick, 'remote_addr', user.remote_addr).fail(handleException);
            delete newData.remote_addr;
        }
        
        user.socket.emit('update', newData);
    }
    
    function showMessage(socket, message, style) {
        socket.emit('message', {
            message : message,
            messageType : style
        });
    }
    
    function roomEmit() {
        room.in('chat').emit.apply(room, arguments);
    }
    
    var COMMANDS = {
        nick : {
            params : ['nick'],
            handler : function (user, params) {
                access.ensureRoleExists(rbac, params.nick, function (err, role) {
                    var index;
                    if (params.nick.length > 0 && params.nick.length < 50 && /^[\x21-\x7E]*$/i.test(params.nick)) {
                        index = findIndex(channel.online, 'nick', params.nick);
                        if (index === -1) {
                            dao.find(params.nick).then(function () {
                                showMessage(user.socket, 'This nick is registered, if this is your nick use /login', 'error');
                            }).fail(function () {
                                updateUserData(user, {
                                    nick : params.nick,
                                    role : 4,
                                    role2 : role
                                });
                            });   
                        } else {
                            showMessage(user.socket, 'That nick is already being used', 'error');
                        }
                    } else {
                        showMessage(user.socket, 'Invalid nick', 'error');
                    }
                });
            }
        },
        login : {
            params : ['nick', 'password'],
            handler : function (user, params) {
                var message,
                    messageType = 'info';

                const then = dao.login(params.nick, params.password).then(function (correctPassword, dbuser) {
                    if (correctPassword) {
                        if (params.nick !== user.nick) {
                            var targetUser = findUserByAttribute(channel.online, 'nick', dbuser.nick);
                            if (targetUser) {
                                targetUser.socket.disconnect();
                            }
                            
                            dao.find(params.nick).then(function (dbuser) {
                                dao.getChannelinfo(channelName).then(function (channelRoles, channelData) {//check for channel roles
                                    if (dbuser.role === 0) {// check if god role
                                        userRole = 0;
                                    } else if (channelRoles[dbuser.nick]) {
                                        if (channelRoles[dbuser.nick] !== 0) {
                                            userRole = channelRoles[dbuser.nick];
                                        } else {
                                            userRole = 4;
                                        }
                                    } else {
                                        userRole = 4;
                                    }
                                    
                                    if (dbuser.hat) {
                                        user.hat = JSON.parse(dbuser.hat).current;
                                    }

                                    access.ensureRoleExists(rbac, dbuser.nick, function (err, role) {
                                        updateUserData(user, {
                                            nick : dbuser.nick,
                                            token : dao.makeId(),
                                            remote_addr : true,
                                            role : userRole,
                                            role2 : role,
                                            flair : dbuser.flair
                                        });
                                    });
                                });
                            });
                        } else {
                            message = "You're already logged in";
                        }
                    } else {
                        message = 'Incorrect password';
                        messageType = 'error';
                    }
                });
                const fail = then.fail(function () {
                    message = "That account doesn't exist";
                    messageType = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message, messageType);
                });
            }
        },
        register : {
            params : ['nick', 'password'],
            handler : function (user, params) {
                if (params.nick.length < 50 && /^[\x21-\x7E]*$/i.test(params.nick)) {
                    if (params.password.length > 4) {
                        dao.findip(user.remote_addr).then(function (accounts) {
                            if (accounts.length < 5) {
                                dao.register(params.nick, params.password, user.remote_addr).then(function () {
                                    showMessage(user.socket, 'account registered', 'info');
                                    updateUserData(user, {
                                        nick : params.nick
                                    });
                                }).fail(function (err) {
                                    showMessage(user.socket, params.nick + ' is already registered', 'error');
                                });
                            } else {
                                showMessage(user.socket, 'Serveral accounts already registered with this IP');
                            }
                        });
                    } else {
                        showMessage(user.socket, 'Please choose a password that is at least 5 characters long', 'error');
                    }
                } else {
                    showMessage(user.socket, 'Invalid nick', 'error');
                }
            }
        },
        me : {
            params : ['message'],
            handler : function (user, params) {
                if (params.message.length < 1000) {
                    roomEmit('message', {
                        message : user.nick + ' ' + params.message,
                        messageType : 'action'
                    });
                }
            }
        },
        whois : {
            params : ['nick'],
            handler : function (user, params) {
                // TODO: collapse
                async.parallel({
                    targetUser: function targetUser (callback) {
                        const targetUser = findUserByAttribute(channel.online, 'nick', params.nick);
                        if (targetUser) {
                            callback(null, targetUser);
                        } else {
                            callback(null, false);
                        }
                    },
                    channelRoles: function channelRoles (callback) {
                        dao.getChannelinfo(channelName).then(function (channelRoles) {
                            callback(null, channelRoles);
                        }).fail(function () {
                            callback(null, false);
                        });
                    },
                    dbuser: function dbuser (callback) {
                        dao.find(params.nick).then(function (dbuser) {
                            callback(null, dbuser);
                        }).fail(function () {
                            callback(new Error('User not found in database'), null);
                        });
                    },
                    can_see_offlineUserIP: function can_see_offlineUserIP (callback) {
                        rbac.can(user.nick, 'view', 'offlineUserIP', function (can) {
                            callback(null, can);
                        });
                    },
                    can_see_onlineUserIP: function can_see_onlineUserIP (callback) {
                        rbac.can(user.nick, 'view', 'onlineUserIP', function (can) {
                            callback(null, can);
                        });
                    }
                }, function whois_finalize(err, res) {
                    var message,
                        rows = {};

                    if (res.targetUser) {
                        rows.nick = res.targetUser.nick;
                        rows.role = res.targetUser.role;
                        rows.ip = (res.can_see_onlineUserIP || user.nick === res.targetUser.nick) ?
                                      res.targetUser.remote_addr :
                                      'Private';
                    }
                    if (res.dbuser) {
                        rows.nick = res.dbuser.nick;
                        rows.role = res.channelRoles[params.nick] || res.dbuser.role;
                        rows.ip = res.can_see_offlineUserIP || user.nick === res.dbuser.nick ? res.dbuser.remote_addr : 'Private';
                        rows.registered = 'Yes';
                    } else {
                        rows.registered = 'No';
                    }

                    if (rows.nick) {
                        var keys = Object.keys(rows);
                        keys.forEach(function (key) {
                            key = key.toString();
                            const valueString = rows[key].toString();
                            var label;
                            if (key === 'ip') {
                                label = key.toUpperCase();
                            } else {
                                label = key.charAt(0).toUpperCase() + key.slice(1);
                            }
                            if (valueString) {
                                rows[key] = label + ': ' + valueString;
                            }
                        });
                        message = [rows.nick,
                                   rows.role,
                                   rows.ip,
                                   rows.registered].join('\n');
                    } else {
                        message = params.nick + " doesn't exist";
                    }

                    showMessage(user.socket, message, 'info');
                });
            }
        },
        change_password : {
            params : ['oldpassword', 'newpassword'],
            handler : function (user, params) {
                if (params.oldpassword && params.newpassword && params.newpassword.length > 3) {
                    dao.login(user.nick, params.oldpassword).then(function (correctPassword, dbuser) {
                        dao.encrypt(params.newpassword).then(function (hash) {
                            dao.setUserinfo(dbuser.nick, 'password', hash).then(function () {
                                showMessage(user.socket, 'Password has been changed', 'info');
                            });
                        });
                    }).fail(function () {
                        showMessage(user.socket, 'Wrong password, if you\'ve forgot your password contact an admin', 'error'); 
                    });
                } else {
                    showMessage(user.socket, 'Please pick a more secure password', 'error');
                }
            }
        },
        kick : {
            params : ['nick', 'reason'],
            permissions : [['kick', 'user']],
            handler : function (user, params) {
                var message,
                    messageType = 'info';
                    targetUserMessage = "You've been kicked: " + (params.reason ? ': ' : '') + params.reason;

                var targetUser = findUserByAttribute(channel.online, 'nick', params.nick);
                if (targetUser) {
                    // TODO: extend rbac
                    if (user.role <= targetUser.role) {
                        roomEmit('message', {
                            message : user.nick + ' kicked ' + params.nick + (params.reason ? ': ' + params.reason : ''),
                            messageType : 'general'
                        });
                        showMessage(targetUser.socket, targetUserMessage, 'error');
                        targetUser.socket.disconnect();
                    } else {
                        message = params.nick + ' is not kickable';
                        messageType = 'error';
                    }
                } else {
                    message = params.nick + ' is not online';
                    messageType = 'error';
                }

                showMessage(user.socket, message, messageType);
            }
        },
        ban : {
            params : ['nick'],
            optionalParams : ['reason'],
            permissions : [['ban', 'user']],
            handler : function (user, params) {
                var message,
                    messageType = 'info';
                    targetUserMessage = "You've been banned: " + (params.reason ? ': ' + params.reason : '');

                var targetUser = findUserByAttribute(channel.online, 'nick', params.nick);
                if (target) {
                    showMessage(targetUser.socket, targetUserMessage, 'error');
                    targetUser.socket.disconnect();
                }

                const then = dao.ban(channelName, params.nick, user.nick, params.reason).then(function () {
                    roomEmit('message', {
                        message : user.nick + ' banned ' + params.nick + (params.reason ? ': ' + params.reason : ''),
                        messageType : 'general'
                    });
                    message = params.nick + ' is now banned';
                });
                const fail = then.fail(function () {
                    message = params.nick + ' is already banned';
                    messageType = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message, messageType);
                });
            }
        },
        banip : {
            params : ['nick', 'reason'],
            permissions : [['banip', 'user']],
            handler : function (user, params) {
                rbac.can(params.nick, 'banip', 'user', function callback_can (err, can) {
                    if (can) {
                        var targetUser = findUserByAttribute(channel.online, 'nick', params.nick),
                            targetUserMessage = "You've been banned" + (params.reason ? ': ' + params.reason : '');
                        
                        if (targetUser) {
                            dao.ban(channelName, targetUser.remote_addr, user.nick, params.reason).then(function () {
                                showMessage(targetUser.socket, message, 'error');
                                targetUser.socket.disconnect();

                                showMessage(user.socket, params.nick + ' is now IP banned', 'info');
                            }).fail(function () {
                                showMessage(user.socket, params.nick + ' is already IP banned', 'error');
                            });
                        }
                    }
                });
            }
        },
        unban : {
            params : ['nick'],
            permissions : [['unban', 'user']],
            handler : function (user, params) {
                rbac.can(params.nick, 'unban', 'user', function callback_can (err, can) {
                    if (can) {
                        dao.unban(channelName, params.nick).then(function () {
                            showMessage(user.socket, params.nick + ' is unbanned', 'info');
                        }).fail(function () {
                            showMessage(user.socket, params.nick + " isn't banned", 'error');
                        });
                    }
                });
            }
        },
        whitelist : {
            params : ['nick'],
            permissions : [['whitelist', 'user']],
            handler : function (user, params) {
                rbac.can(params.nick, 'whitelist', 'user', function callback_can(err, can) {
                    if (can) {
                        dao.find(params.nick).then(function (dbuser) {
                            dao.getChannelAtt(channelName, 'whitelist').then(function (whitelist) {
                                if (whitelist === undefined) {
                                    whitelist = [];
                                }
                                if (whitelist.indexOf(user.nick) === -1) {
                                    whitelist.push(params.nick);
                                    dao.setChannelinfo(channelName, 'whitelist', whitelist).then(function () {
                                        showMessage(user.socket, params.nick + ' is now whitelisted');
                                    });
                                } else {
                                    showMessage(user.socket, params.nick + ' is already whitelisted', 'error');
                                }
                            });
                        }).fail(function () {
                            showMessage(user.socket, user.nick + ' is not registered', 'error'); 
                        });
                    }
                });
            }
        },
        unwhitelist : {
            params : ['nick'],
            permissions : [['unwhitelist', 'user']],
            handler : function (user, params) {
                rbac.can(params.nick, 'unwhitelist', 'user', function callback_can(err, can) {
                    if (can) {
                        dao.getChannelAtt(channelName, 'whitelist').then(function (whitelist) {
                            if (whitelist === undefined) {
                                whitelist = [];
                            }
                            var index = whitelist.indexOf(params.nick);
                            if (index !== -1) {
                                whitelist.splice(index, 1);
                                dao.setChannelinfo(channelName, 'whitelist', whitelist).then(function () {
                                    showMessage(user.socket, params.nick + ' has been unwhitelisted');
                                });
                            } else {
                                showMessage(user.socket, params.nick + ' isn\'t whitelisted', 'error');
                            }
                        });
                    }
                });
            }
        },
        delete : {
            params : ['nick'],
            permissions : [['delete', 'user']],
            handler : function (user, params) {
                rbac.can(params.nick, 'delete', 'user', function callback_can(err, can) {
                    if (can) {
                        dao.unregister(params.nick).then(function () {
                            showMessage(user.socket, dbuser.nick + ' has been deleted.');
                        }).fail(function () {
                            showMessage(user.socket, params.nick + " isn't registered.", 'error');
                        });
                    }
                });
            }
        },
        global : {
            params : ['message'],
            permissions : [['send', 'globalMessage']],
            handler : function(user, params){
                rbac.can(params.nick, 'send', 'globalMessage', function callback_can(err, can) {
                    if (can) {
                        if (params.message.length < 1000) {
                            io.emit('message',{
                                message : params.message,
                                messageType : 'general'
                            });
                        } else {
                            showMessage(user.socket, 'message too long');
                        }
                    }
                });
            }
        },
        find : {
            params : ['ip'],
            permissions : [['view', 'offlineUserIP']],
            handler : function (user, params) {
                var message,
                    messageType = 'info',
                    IP = params.ip;
                
                function findAccounts (ip) {
                    dao.findip(ip).then(function (accounts) {
                        if (accounts && accounts.length) {
                            message = 'IP ' + ip + ' matched accounts: ' + accounts.join(', ');
                        } else {
                            message = 'No accounts matched this ip.';
                            messageType = 'error';
                        }
                        showMessage(user.socket, message, messageType);
                    });
                }

                if (IP.split('.').length !== 4) {//if paramter doesn't have 4 dots its a nick
                    var targetUser = findUserByAttribute(channel.online, 'nick', IP);
                    if (targetUser) {
                        findAccounts(targetUser.remote_addr);
                    } else {
                        dao.find(IP).then(function (dbuser) {
                            findAccounts(dbuser.remote_addr);
                        }).fail(function () {
                            showMessage(user.socket, 'No accounts matched this nick.', 'error');
                        });
                    }
                } else {
                    findAccounts(IP);
                }
            }
        },
        refresh : {
            permissions : [['refresh', 'view']],
            handler : function (user) {
                var i;
                
                roomEmit('refresh');
                for (i = 0; i < channel.online.length; i++) {
                    channel.online[i].socket.disconnect();
                }
                channel.online = [];
            }
        },
        // TODO: generalize with revoke
        grant : {
            params : ['role', 'role|permission'],
            permissions : [['grant', 'permission']],
            handler : function grant(user, params) {
                async.parallel({
                    user_role: function user_role (callback) {
                        access.ensureRoleExists(rbac, params.role, function (err, role2) {
                            if (!err) {
                                callback(null, role2);
                            } else {
                                callback(err, null);
                            }
                        });
                    },
                    role_or_permission: function role_or_permission (callback) {
                        rbac.get(params['role|permission'], function (err, got) {
                            if (!err) {
                                callback(null, got);
                            } else {
                                callback(err, null);
                            }
                        });
                    }
                }, function grant_finalize(err, res) {
                    var message;

                    if (res.user_role) {
                        if (res.role_or_permission) {
                            rbac.grant(res.user_role, res.role_or_permission, function (err, success) {
                                var message;
                                if (success) {
                                    message = params.role + ' has been granted ' + params['role|permission'];
                                } else {
                                    message = "can't grant " + params.role + ' ' + params['role|permission'];
                                }
                                showMessage(user.socket, message, 'info');
                            });
                        } else {
                            message = 'role|permission ' + params['role|permission'] + " doesn't exist";
                        }
                    } else {
                        message = 'role for ' + params.nick + " doesn't exist";
                    }

                    showMessage(user.socket, message, 'info');
                });
            }
        },
        // TODO: add revoking a permission from a role while keeping the other permissions
        revoke : {
            params : ['role', 'role|permission'],
            permissions : [['revoke', 'permission']],
            handler : function revoke(user, params) {
                async.parallel({
                    user_role: function user_role (callback) {
                        access.ensureRoleExists(rbac, params.role, function (err, role2) {
                            if (!err) {
                                callback(null, role2);
                            } else {
                                callback(err, null);
                            }
                        });
                    },
                    role_or_permission: function role_or_permission (callback) {
                        rbac.get(params['role|permission'], function (err, got) {
                            if (!err) {
                                callback(null, got);
                            } else {
                                callback(err, null);
                            }
                        });
                    }
                }, function (err, res) {
                    var message;

                    if (res.user_role) {
                        if (res.role_or_permission) {
                            rbac.revoke(res.user_role, res.role_or_permission, function callback_revoke (err, success) {
                                if (success) {
                                    message = 'revoked ' + params['role|permission'] + ' rights from ' + params.nick;
                                } else {
                                    message = "can't revoke " + params['role|permission'] + ' rights from ' + params.nick;
                                }
                            });
                        } else {
                            message = 'role|permission ' + params['role|permission'] + " doesn't exist";
                        }
                    } else {
                        message = 'role for nick ' + params.role + " doesn't exist";
                    }

                    showMessage(user.socket, message, 'info');
                });
            }
        },
        can : {
            params : ['role', 'action', 'resource'],
            handler : function can(user, params) {
                rbac.can(params.role, params.action, params.resource, function callback_can (err, can) {
                    var message = params.role;
                    if (can) {
                        message += ' can ';
                    } else {
                        message += " can't ";
                    }
                    message += params.action + ' ' + params.resource;
                    showMessage(user.socket, message, 'info');
                });
            }
        },
        has : {
            params : ['role', 'child_role'],
            handler : function has(user, params) {
                rbac.hasRole(params.role, params.child_role, function callback_has (err, has) {
                    var message = params.role;
                    if (has) {
                        message += ' has ';
                    } else {
                        message += " doesn't have ";
                    }
                    message += params.child_role;
                    showMessage(user.socket, message, 'info');
                });
            }
        },
        cans : {
            params : ['role'],
            handler : function cans(user, params) {
                rbac.getScope(params.role, function callback_getScope (err, cans) {
                    var message = params.role + ' can ' + cans.join(", ");
                    showMessage(user.socket, message, 'info');
                });
            }
        },
        grants : {
            params : ['role'],
            handler : function grants(user, params) {
                rbac.storage.getGrants(params.role, function callback_getGrants (err, grants) {
                    var message = 'grants for ' + params.role + ': ';

                    if (!err && grants) {
                        grants.forEach(function (grant, i) {
                            grants[i] = grant.name;
                        });
                        message += grants.join(", ");
                    }

                    showMessage(user.socket, message, 'info');
                });
            }
        },/*
        access : {
            role : 1,
            params : ['nick', 'role'],
            handler : function (user, params) {
                rbac.can(user.nick, 'grant', 'user', function callback_can(err, can) {
                    var message,
                        messageType = 'info';

                    if (can) {
                        var role = parseInt(params.role, 10);
                        if (role > 0 && role < 5) {
                            dao.find(params.nick).then(function () {
                                dao.setChannelRole(channelName, params.nick, role).then(function () {
                                    var targetUser = findUserByAttribute(channel.online, 'nick', params.nick);
                                    if (targetUser) {
                                        targetUser.role = parseInt(role, 10);
                                        message = params.nick + ' now has role ' + role;
                                        showMessage(targetUser.socket, 'role is now set to ' + role, 'info');
                                    }
                                });
                            }).fail(function () {
                                message = "That user isn't registered";
                                messageType = 'error';
                            }).then(function () {
                                showMessage(user.socket, message, messageType);
                            });
                        }
                    } else {
                        message = "You can't do that";
                        messageType = 'error';
                        // TODO: collapse into single endpoint
                        showMessage(user.socket, message, messageType);
                    }
                });
            }
        },*/
        pm : {
            params : ['nick', 'message'],
            permissions : [['send', 'pm']],
            handler : function (user, params) {
                var targetUser = findUserByAttribute(channel.online, 'nick', params.nick);
                
                if (params.message && params.message.length < 10000) {
                    if (targetUser) {
                        targetUser.socket.emit('message', {
                            message : ' ' + params.message,
                            messageType : 'personal',
                            nick : user.nick
                        });

                        if (targetUser.id !== user.id) {
                            user.socket.emit('message', {
                                message : ' ' + params.message,
                                messageType : 'personal',
                                nick : user.nick
                            });   
                        }
                    } else {
                        showMessage(user.socket, 'That user isn\'t online', 'error');
                    }
                }
            }
        },
        banlist : {
            permissions : [['view', 'banlist']],
            handler : function (user) {
                dao.banlist(channelName).then(function (banlist, banData) {
                    user.socket.emit('banlist', banData);
                });
            }
        },
        give_hat : {
            role : 0,
            params : ['nick', 'hat'],
            handler : function (user, parmas) {
                var allHats,
                    hatIndex,
                    hatName,
                    usersHats,
                    userIndex;
                    
                dao.find(parmas.nick).then(function (dbuser) {
                    allHats = dao.getHats();
                    hatIndex = allHats.lowercase.indexOf(parmas.hat.toLowerCase());
                    
                    if (dbuser.hat) {
                        try {
                            usersHats = JSON.parse(dbuser.hat);
                        } catch (err) {
                            usersHats = {
                                available : [''],
                                current : ''
                            };
                        }
                    } else {
                        usersHats = {
                            available : [''],
                            current : ''
                        };
                    }
                    
                    if (hatIndex !== -1) {
                        hatName = allHats.lowercase[hatIndex];
                        if (usersHats.available.indexOf(hatName) === -1) {
                            usersHats.available.push(hatName);
                            dao.setUserinfo(dbuser.nick, 'hat', usersHats).then(function () {
                                userIndex = findIndex(channel.online, 'nick', dbuser.nick);
                                if (userIndex !== -1) {
                                    showMessage(channel.online[userIndex].socket, 'You now have access to hat: ' + hatName, 'info');
                                }
                                showMessage(user.socket, user.nick + ' now has access to ' + hatName, 'info');
                            });
                        } else {
                            showMessage(user.socket, user.nick + ' already has access to ' + hatName, 'info');
                        }
                    } else {
                        showMessage(user.socket, 'That hat doesn\'t exist', 'error');
                    }
                }).fail(function () {
                    showMessage(user.socket, 'That user isn\'t registered', 'error');
                });
            }
        },
        remove_hat : {
            params : ['nick', 'hat'],
            handler : function (user, params) {
                var usersHats,
                    userHatIndex,
                    hatIndex,
                    hatName,
                    allHats,
                    userIndex;
                
                
                dao.find(params.nick).then(function (dbuser) {
                    if (dbuser.hat) {
                        usersHats = JSON.parse(dbuser.hat);
                        hatName = params.hat.toLowerCase();
                        hatIndex = usersHats.available.indexOf(hatName);
                        
                        if (hatIndex !== -1) {
                            usersHats.available.splice(hatIndex, 1);
                            
                            if (usersHats.current.slice(0, -4).toLowerCase() === hatName) {
                                usersHats.current = 'none';
                                user.hat = 'none';
                            }
                            
                            dao.setUserinfo(params.nick, 'hat', usersHats).then(function () {
                                userIndex = findIndex(channel.online, 'nick', dbuser.nick);
                                
                                if (userIndex !== -1) {
                                    showMessage(channel.online[userIndex].socket, 'You no longer have access to hat: ' + hatName, 'info');
                                }
                                showMessage(user.socket, hatName + ' hat removed', 'info'); 
                            });
                        } else {
                            showMessage(user.socket, dbuser.nick + ' doesn\'t have hat: ' + hatName, 'info');
                        }
                    } else {
                        showMessage(user.socket, 'User doesn\'t have any hats', 'error'); 
                    }
                }).fail(function () {
                    showMessage(user.socket, 'That user isn\'t registered', 'error');
                });
                
            }
        },
        hat : {
            params : ['hat'],
            handler : function (user, params) {
                var usersHats,
                    userHatIndex,
                    hatIndex,
                    allHats,
                    hatName;
                    
                dao.find(user.nick).then(function (dbuser) {
                    if (dbuser.hat) {
                        allHats = dao.getHats();
                        usersHats = JSON.parse(dbuser.hat);
                        hatIndex = allHats.lowercase.indexOf(params.hat.toLowerCase());
                        
                        if (hatIndex !== -1) {
                            userHatIndex = usersHats.available.indexOf(allHats.lowercase[hatIndex]);
                            
                            if (userHatIndex !== -1) {
                                hatName = allHats.name[hatIndex];
                            }
                        } else if (params.hat.toLowerCase() === 'none') {
                            hatName = 'none';
                        }
                        
                        if (hatName) {
                            usersHats.current = hatName;                            
                            dao.setUserinfo(dbuser.nick, 'hat', usersHats).then(function () {
                                user.hat = usersHats.current;
                                showMessage(user.socket, 'You are now wearing hat: ' + usersHats.current, 'info');
                            });
                        } else {
                            showMessage(user.socket, 'You don\'t have access to that hat', 'error');
                        }
                    } else {
                        showMessage(user.socket, 'You don\'t have any hats', 'error'); 
                    }
                }).fail(function () {
                    showMessage(user.socket, 'Must be registered to own a hat', 'error'); 
                });
            }
        },
        hatlist : {
            params : ['nick'] ,
            handler : function (user, params) {
                var usersHats;
                
                dao.find(params.nick).then(function (dbuser) {
                    if (dbuser.hat) {
                        usersHats = JSON.parse(dbuser.hat);
                        if (usersHats.available.length) {
                            showMessage(user.socket, dbuser.nick + ' has hats: ' + usersHats.available.join(', '), 'info');
                        } else {
                            showMessage(user.socket, params.nick + ' doesn\'t have any hats', 'info');
                        }
                    } else {
                        showMessage(user.socket, params.nick + ' doesn\'t have any hats', 'info');
                    }
                }).fail(function () {
                    showMessage(user.socket, params.nick + ' isn\'t registered', 'error');
                });
            }
        },
        afk : {
            params : ['message'],
            handler : function (user, params) {
                if (params.message.length < 200) {
                    if (params.message === 'none') {
                        delete user.afk;
                    } else {
                        user.afk = params.message;
                    }
                    roomEmit('afk', user.id, user.afk);
                }
            }
        },
        cursors : {
            role: 0,
            handler : function (user) {
                var allCursors = dao.getCursors().lowercase;
                var b = allCursors.pop();
                showMessage(user.socket, 'Cursors available: ' + allCursors.join(", ") + 'and ' + b + '.');
            }
        },
        cursor : {
            params : ['cursor'],
            handler : function (user, params) {
                var usersCursors,
                    userCursorIndex,
                    cursorIndex,
                    allCursors;
                    
                dao.find(user.nick).then(function (dbuser) {
                    var allCursors = dao.getCursors();
                    var cursorIndex = allCursors.lowercase.indexOf(params.cursor.toLowerCase());
                    if (cursorIndex !== -1) {
                        var userCursor = {
                            "name": allCursors.name[cursorIndex]
                        }
                        dao.setUserinfo(dbuser.nick, 'cursor', userCursor).then(function () {
                            user.cursor = allCursors.name[cursorIndex];
                            roomEmit("changeCursor", user.id, user.cursor);
                            showMessage(user.socket, 'You are now using cursor: ' + allCursors.lowercase[cursorIndex], 'info');
                        });
                    } else {
                        showMessage(user.socket, 'That cursor doesn\'t exist.', 'error');
                    }
                }).fail(function () {
                    var allCursors = dao.getCursors();
                    var cursorIndex = allCursors.lowercase.indexOf(params.cursor.toLowerCase());
                    if (cursorIndex !== -1) {
                        var userCursor = {
                            "name": allCursors.name[cursorIndex]
                        }
                        user.cursor = allCursors.name[cursorIndex];
                        roomEmit("changeCursor", user.id, user.cursor);
                        showMessage(user.socket, 'You are now using cursor: ' + allCursors.lowercase[cursorIndex], 'info');
                    } else {
                        showMessage(user.socket, 'That cursor doesn\'t exist.', 'error');
                    }
                });
            }
        },
        flair : {
            params : ['flair'],
            handler : function (user, params) {
                dao.setUserinfo(user.nick, 'flair', params.flair);
            }
        }
    };
    
    room.on('connection', function (socket) {
        
        var user = {
            remote_addr : socket.conn.remoteAddress,
            socket : socket,
            role : 4,
            id : dao.makeId()
        };
        
        if (socket.request.headers['cf-connecting-ip']) {//if header is present replace clients ip with header
            user.remote_addr = socket.request.headers['cf-connecting-ip'];
        }
        
        socket.on('updateCursor', function (cursorData) {
            if (findIndex(channel.online, 'id', user.id) !== -1 && typeof cursorData === 'object') {
                if (!isNaN(parseInt(cursorData.y)) && !isNaN(parseInt(cursorData.x))) {
                    roomEmit('updateCursor', {
                        id : user.id,
                        position : cursorData
                    });
                }
            }
        });
        
        socket.on('removeCursor', function(){
            if (findIndex(channel.online, 'id', user.id) !== -1) {
                roomEmit('removeCursor', user.id);
            }
        });
        
        socket.on('message', function (message, flair) {
            throttle.on(user.remote_addr + '-message').then(function (notSpam) {
                if (notSpam) {
                    if (findIndex(channel.online, 'id', user.id) != -1) {
                        if (typeof message === 'string' && (typeof flair === 'string' || !flair)) {
                            if (message.length < 10000 && (flair && flair.length < 500 || !flair)) {
                                roomEmit('message', {
                                    message : message,
                                    messageType : 'chat',
                                    nick : user.nick,
                                    flair : flair,
                                    hat : user.hat,
                                    count : ++channel.messageCount
                                });      
                            }
                        }   
                    }
                } else {
                    showMessage(user.socket,'You are spamming, stop or you will be temporarily banned.', 'error');
                    throttle.warn(user.remote_addr + '-message');
                }
            }).fail(function () {
                dao.ban(channelName,user.remote_addr,'Throttle', 'Message spamming');
                showMessage(user.socket, 'You have been banned for spamming.','error');
                socket.disconnect();
            });
        });
        
        socket.on('message-image', function (message, flair) {
            var acceptedFiletypes = ["image/png", "image/jpg", "image/jpeg", "image/gif", "image/webp"];
            throttle.on(user.remote_addr + '-message').then(function (notSpam) {
                if (notSpam) {
                    if (findIndex(channel.online, 'id', user.id) != -1) {
                        if (message && typeof message.type === 'string' && acceptedFiletypes.indexOf(message.type) != -1 &&typeof message.img === 'string' && (typeof flair === 'string' || !flair)) {
                            if (message.img.length < 7000001) {
                                if (flair && flair.length < 500 || !flair) {
                                    roomEmit('message', {
                                        message : message,
                                        messageType : 'chat-image',
                                        nick : user.nick,
                                        flair : flair,
                                        hat : user.hat,
                                        count : ++channel.messageCount
                                    });      
                                }
                            }
                        }   
                    }
                } else {
                    showMessage(user.socket,'You are spamming, stop or you will be temporarily banned.', 'error');
                    throttle.warn(user.remote_addr + '-message');
                }
            }).fail(function () {
                dao.ban(channelName,user.remote_addr,'Throttle', 'Message spamming');
                showMessage(user.socket, 'You have been banned for spamming.','error');
                socket.disconnect();
            });
        });
        
        socket.on('typing', function(typing) {
            roomEmit('typing', user.id, typing);
        });
        
        socket.on('activeChannels', function () {
            var channelInfo = [],
                channelKeys = Object.keys(channels),
                i;
            
            for (i = 0; i < channelKeys.length; i++) {
                if (channels[channelKeys[i]].online.length) {
                    channelInfo.push({
                        name : channelKeys[i],
                        online : channels[channelKeys[i]].online.length
                    });   
                }
            }
            
            user.socket.emit('activeChannels', channelInfo);
        });
        
        socket.on('privateMessage', function (message, flair, userID) {
            if (typeof message === 'string' && (!flair || typeof flair === 'string') && typeof userID === 'string') {
                if (message.length < 10000 && (!flair || flair.length < 500)) {
                    var targetUser = findUserByAttribute(channel.online, 'id', userID);
                    if (targetUser) {
                        targetUser.socket.emit('pmMessage', {
                            message : message,
                            messageType : 'chat',
                            nick : user.nick,
                            flair : flair,
                            landOn : user.id
                        });
                        if (user.id !== userID) {
                            user.socket.emit('pmMessage', {
                                message : message,
                                messageType : 'chat',
                                nick : user.nick,
                                flair : flair,
                                landOn : userID
                            });
                        }
                    }
                }
            }
        });
        
        function handleCommand(command, params) {
            var valid = true,
                i;
            
            // if (command.role === undefined || command.role >= user.role) {
            function callback_handleCommand(err, can) {
                if (can) {
                    if (command.params) {
                        for (i = 0; i < command.params.length; i++) {
                            if (typeof params[command.params[i]] !== 'string' && (command.optionalParams && typeof params[command.optionalParams[i]] !== 'string')) {
                                valid = false;
                            }
                        }

                        if (valid) {
                            command.handler(user, params);
                        }
                    } else {
                        command.handler(user);
                    }
                } else {
                    showMessage(user.socket, "Don't have access to this command", 'error');
                }
            }
            if (command.hasOwnProperty('permissions')) {
                rbac.canAll(user.role2.name, command.permissions, callback_handleCommand);
            } else {
                callback_handleCommand(null, true);
            }
        }

        socket.on('command', function (commandName, params) {
            throttle.on(user.remote_addr + '-command').then(function (notSpam) {
                if (notSpam) {
                    if (typeof commandName === 'string' && COMMANDS[commandName]) {
                        if (!params || typeof params === 'object') {
                            handleCommand(COMMANDS[commandName], params);
                        }
                    }
                } else {
                    showMessage(user.socket, 'You are spamming, stop or you will be temporarily banned.', 'error');
                    throttle.warn(user.remote_addr);
                }
            }).fail(function () {
                dao.ban(channelName, user.remote_addr, 'Throttle', 'Command spamming');
                showMessage(user.socket,'You have been banned for spamming.', 'error');
                socket.disconnect();
            });
        });
                
        socket.on('channelStatus', function (settings) {
            var validSettings = {
                lock : {
                    type : 'boolean',
                    role : 1
                },
                proxy : {
                    type : 'boolean',
                    role : 1
                },
                topic : {
                    type : 'string',
                    role : 3
                },
                note : {
                    type : 'string',
                    role : 1
                },
                background : {
                    type : 'string',
                    role : 2
                },
                themecolors : {
                    type : 'object',
                    role : 2
                }
            },
                keys = Object.keys(settings),
                valid = true,
                errorMessage,
                formatSettings = {};
            
            if (typeof settings === 'object') {
                for (var i = 0; i < keys.length; i++) {
                    if (validSettings[keys[i]]) {
                        if (typeof settings[keys[i]] === validSettings[keys[i]].type) {
                            if (user.role <= validSettings[keys[i]].role) {
                                formatSettings[[keys[i]]] = {
                                    value : settings[keys[i]],
                                    updatedBy : user.nick,
                                    date : new Date().getTime()
                                }
                            } else {
                                valid = false;
                                errorMessage = 'Don\'t have access for this command';
                            }
                        } else {
                            valid = false;
                            errorMessage = 'Invalid settings';
                        }
                    } else {
                        valid = false;
                        errorMessage = 'Invalid settings 2';
                    }
                }
                
                if (valid) {
                    dao.setChannelinfo(channelName, formatSettings).then(function () {
                        roomEmit('channeldata', {
                            data : formatSettings
                        });
                    }).fail(handleException);     
                } else {
                    showMessage(user.socket, errorMessage, 'error');
                }
            }
        });
        
        function joinChannel(userData, dbuser, channelData) {
            var i,
                onlineUsers = [],
                roleNames = ['God', 'Channel Owner', 'Admin', 'Mod', 'Basic'];
            
            if (!userData) userData = {};
            
            function join(channelData, nick, role, hat, cursor) {
                user.nick = nick;
                user.role = role;
                user.token = dao.makeId();
                user.hat = hat && hat.current;
                user.cursor = cursor;
                tokens[user.nick] = user.token;

                access.ensureRoleExists(rbac, nick, function (err, user_role) {
                    rbac.grant(user_role, role_basic, function(){});
                    user.role2 = user_role;
                    for (i = 0; i < channel.online.length; i++) {
                        onlineUsers.push({
                            nick : channel.online[i].nick,
                            id : channel.online[i].id,
                            afk : channel.online[i].afk
                        });
                    }

                    channel.online.push(user);
                    
                    socket.join('chat');
                    
                    socket.emit('channeldata', {
                        users : onlineUsers,
                        data : channelData
                    });
                    
                    socket.emit('update', {
                        nick : user.nick,
                        role : roleNames[user.role],
                        token : user.token,
                        hats : hat
                    });
                    
                    roomEmit('joined', user.id, user.nick);
                    console.log('USER JOIN', nick, user.role, user.remote_addr);
                });
            }
            
            if (userData.nick && userData.nick.length > 0 && userData.nick.length < 50 && /^[\x21-\x7E]*$/i.test(userData.nick)) {
                var targetUser = findUserByAttribute(channel.online, 'nick', userData.nick);
                
                if (targetUser) {
                    if (dbuser) {
                        userData.role = dbuser.role;
                        
                        if (dbuser.hat) {
                            userData.hat = JSON.parse(dbuser.hat);
                        }
                        
                        if (dbuser.cursor) {
                            userData.cursor = JSON.parse(dbuser.cursor).name;
                        }
                    }
                } else {
                    userData.nick = dao.getNick();
                }
            } else {
                userData.nick = dao.getNick();
            }
            
            if (userData.role === undefined) {
                userData.role = 4;
            }
            
            join(channelData, userData.nick, userData.role, userData.hat, userData.cursor);
        }
        
        function checkChannelStatus (joinData, dbuser) {
            var apiLink = 'http://check.getipintel.net/check.php?ip=' + user.remote_addr + '&contact=theorignalsandwich@gmail.com&flags=m';
            
            dao.banlist(channelName).then(function (nicks) {
                if (nicks.indexOf(user.nick) == -1 && nicks.indexOf(user.remote_addr) == -1) {
                    dao.getChannelinfo(channelName).then(function (channelRoles, channelData) {
                        if (dbuser && dbuser.role !== 0 && channelRoles[dbuser.nick]) {//assign channel role
                            dbuser.role = channelRoles[dbuser.nick];
                        }

                        function attemptJoin () {
                            if (channelData.lock && channelData.lock.value) {
                                if (dbuser && dbuser.nick) {
                                    joinChannel(joinData, dbuser, channelData);
                                } else {
                                    socket.emit('locked');
                                }
                            } else {
                                joinChannel(joinData, dbuser, channelData);
                            }
                        }

                        if (channelData.proxy && channelData.proxy.value) {
                            request(apiLink, function (error, response, body) {
                                if (!error) {
                                    if (!parseInt(body)) {
                                        showMessage(user.socket, 'Sorry but this channel has proxies blocked for now.', 'error');
                                    } else {
                                        attemptJoin();
                                    }
                                }
                            });
                        } else {
                            attemptJoin();
                        }
                    });
                }
            });
            
        }
        
        function checkUserStatus (joinData) {
            if (findIndex(channel.online, 'id', user.id) === -1) {
                if (joinData.nick) {
                    dao.find(joinData.nick).then(function (dbuser) {//find if user exist
                        if (joinData.token && joinData.token === tokens[joinData.nick]) {//tokens match? good to go
                            checkChannelStatus(joinData, dbuser);
                        } else if (joinData.password) {//tokens don't match try logging in with password
                            dao.login(joinData.nick, joinData.password).then(function (correctPassword) {
                                if (correctPassword) {
                                    checkChannelStatus(joinData, dbuser);
                                } else {
                                    checkChannelStatus();
                                }
                            }).fail(checkChannelStatus);
                        } else {
                            delete joinData.nick;
                            checkChannelStatus(joinData);
                        }
                    }).fail(checkChannelStatus.bind(null, joinData));
                } else {
                    checkChannelStatus();
                } 
            } else {
                showMessage(socket, 'Only one socket connection allowed', 'error');
            }
        }
        
        socket.on('requestJoin', function (requestedData) {
            var joinData = {},
                requestedDataKeys,
                k,
                accept = ['nick', 'token', 'password'];
            
            if (typeof requestedData === 'object') {//makes sure requestedData is valid, all items are strings
                requestedDataKeys = Object.keys(requestedData);
                for (k = 0; k < requestedDataKeys.length; k++) {
                    if (accept.indexOf(requestedDataKeys[k]) !== -1 && typeof requestedData[requestedDataKeys[k]] === 'string') {
                        joinData[requestedDataKeys[k]] = requestedData[requestedDataKeys[k]]
                    }
                }
            }
            
            throttle.on(user.remote_addr + '-join', 3).then(function (notSpam) {
                if (notSpam) {
                    checkUserStatus(joinData);
                } else {
                    showMessage(socket, 'You are spamming, stop or you will be temporarily banned.', 'error');
                    throttle.warn(user.remote_addr + '-join');
                }
            }).fail(function () {
                dao.ban(channelName, user.remote_addr, 'Throttle', 'Join spamming');
                showMessage(socket, 'You have been banned for spamming.', 'error');
                socket.disconnect();
            });
        });
        
        socket.on('disconnect', function () {
            var index = findIndex(channel.online, 'nick', user.nick);
            if (index !== -1) {
                roomEmit('left', user.id);
                channel.online.splice(index, 1);
            }
        });
        
    });
    
    return channel;
}

function intoapp(app, http) {
    var channelRegex = /^\/(\w*\/?)$/;
    var io = require('socket.io')(http);
    app.use(express.static(__dirname + '/public'));
    app.get(channelRegex, function (req, res) {
        if (!channels[req.url]) {
            channels[req.url] = createChannel(io, req.url);
        }
        var index = fs.readFileSync('index.html').toString();
        res.send(index);
    });
}

(function () {
    var app = express();
    var http = require('http').Server(app);
    var port = (process.env.PORT || 80);
    http.listen(port, function () {
       console.log('listening on *:'+port);
       intoapp(app, http);
    });
})();