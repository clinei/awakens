var dao = require('./dao');
var request = require('request');
var throttle = require('./throttle');
var _ = require('underscore');
var express = require('express');
var fs = require('fs');
var access = require('./access');
var RBAC = require('rbac');

var channels = {};
var tokens = {};

/*
TODO: investigate user /nick to existing non-nick role
TODO: dependecies pass like in plugin system, through params
TODO: /roles and /perms commands
*/

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

    access.defaultRules.storage = new RBAC.MySQL(dao.settings);
    var rbac = new access.RBAC(access.defaultRules);
    var role_basic;
    // BUGS: race condition
    rbac.getRole('basic', function(err, role) {
        role_basic = role;
    });
    
    function updateUserData(user, newData) {
        if (newData.nick) {
            user.nick = newData.nick;
            roomEmit('nick', user.id, user.nick);
        }
        
        if (newData.token) {
            tokens[user.nick] = newData.token;
        }

        if (newData.role) {
            user.role = newData.role;
            delete newData.role;
        }
        
        if (newData.remote_addr) {//if true save current ip to database
            dao.setUserinfo(user.nick, 'remote_addr', user.remote_addr).catch(handleException);
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
                var message = {
                    type: 'info'
                };

                access.ensureRoleExists(rbac, params.nick).then(function (role) {
                    if (params.nick.length > 0 && params.nick.length < 50 && /^[\x21-\x7E]*$/i.test(params.nick)) {
                        var index = findIndex(channel.online, 'nick', params.nick);
                        if (index === -1) {
                            dao.find(params.nick).then(function () {
                                message.text = 'This nick is registered, if this is your nick use /login';
                                message.type = 'error';
                            }).catch(function () {
                                role.grant(role_basic, function() {
                                    updateUserData(user, {
                                        nick : params.nick,
                                        role : role
                                    });
                                });
                            });   
                        } else {
                            message.text = 'That nick is already being used';
                            message.type = 'error';
                        }
                    } else {
                        message.text = 'Invalid nick';
                        message.type = 'error';
                    }
                });

                showMessage(user.socket, message.text, message.type);
            }
        },
        login : {
            params : ['nick', 'password'],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                const then = dao.login(params.nick, params.password).then(function (correctPassword, dbuser) {
                    if (correctPassword) {
                        if (params.nick !== user.nick) {
                            var targetUser = findUserByAttribute(channel.online, 'nick', dbuser.nick);
                            if (targetUser) {
                                targetUser.socket.disconnect();
                            }
                            
                            Promise.all([dao.find(params.nick), dao.getChannelinfo(channelName)]).then(function (values) {
                                const dbuser = values[0],
                                      channelinfo = values[1];

                                if (dbuser.hat) {
                                    user.hat = JSON.parse(dbuser.hat).current;
                                }

                                access.ensureRoleExists(rbac, dbuser.nick).then(function (role) {
                                    updateUserData(user, {
                                        nick : dbuser.nick,
                                        token : dao.makeId(),
                                        remote_addr : true,
                                        role : role,
                                        flair : dbuser.flair
                                    });
                                });
                            });
                        } else {
                            message.text = "You're already logged in";
                        }
                    } else {
                        message.text = 'Incorrect password';
                        message.type = 'error';
                    }
                });
                const fail = then.catch(function () {
                    message.text = "That account doesn't exist";
                    message.type = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        register : {
            params : ['nick', 'password'],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                if (params.nick.length < 50 && /^[\x21-\x7E]*$/i.test(params.nick)) {
                    if (params.password.length > 4) {
                        dao.findip(user.remote_addr).then(function (accounts) {
                            if (accounts.length < 5) {
                                dao.register(params.nick, params.password, user.remote_addr).then(function () {
                                    message.text = 'account registered';
                                    updateUserData(user, {
                                        nick : params.nick
                                    });
                                }).catch(function (err) {
                                    message.text = params.nick + ' is already registered';
                                    message.type = 'error';
                                });
                            } else {
                                message.text = 'Too many accounts already registered with this IP';
                                message.type = 'error';
                            }
                        });
                    } else {
                        message.text = 'Please choose a password that is at least 5 characters long';
                        message.type = 'error';
                    }
                } else {
                    message.text = 'Invalid nick';
                    message.type = 'error';
                }

                showMessage(user.socket, message.text, message.type);
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
                const targetUser = findUserByAttribute(channel.online, 'nick', params.nick);
                Promise.all([
                    dao.getChannelinfo(channelName),
                    dao.find(params.nick),
                    rbac.canPromise(user.nick, 'see', 'offlineUserIP'),
                    rbac.canPromise(user.nick, 'see', 'onlineUserIP')
                ]).then(function whois_finalize(values) {
                    var message = {
                        type: 'info'
                    };
                    var rows = {};

                    const channel = values[0],
                          dbuser = values[1],
                          can_see_onlineUserIP = values[2],
                          can_see_offlineUserIP = values[3];

                    if (targetUser) {
                        rows.nick = targetUser.nick;
                        rows.role = targetUser.role;
                        rows.ip = (can_see_onlineUserIP || user.nick === targetUser.nick) ?
                                      targetUser.remote_addr :
                                      'Private';
                    }
                    if (dbuser) {
                        rows.nick = dbuser.nick;
                        rows.role = channel.roles[params.nick] || dbuser.role;
                        rows.ip = can_see_offlineUserIP || user.nick === dbuser.nick ? dbuser.remote_addr : 'Private';
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
                        message.text = params.nick + " doesn't exist";
                    }

                    showMessage(user.socket, message, 'info');
                });
            }
        },
        change_password : {
            params : ['oldpassword', 'newpassword'],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                if (params.oldpassword && params.newpassword && params.newpassword.length > 3) {
                    dao.login(user.nick, params.oldpassword).then(function (correctPassword, dbuser) {
                        dao.encrypt(params.newpassword).then(function (hash) {
                            dao.setUserinfo(dbuser.nick, 'password', hash).then(function () {
                                message.text = 'Password has been changed';
                            });
                        });
                    }).catch(function () {
                        message.text = "Wrong password, if you've forgot your password contact an admin";
                        message.type = 'error';
                    });
                } else {
                    message.text = 'Please pick a more secure password';
                    message.type = 'error';
                }
                showMessage(user.socket, message.text, message.type);
            }
        },
        kick : {
            params : ['nick', 'reason'],
            permissions : [['kick', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };
                var targetUserMessage = "You've been kicked: " + (params.reason ? ': ' : '') + params.reason;

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
                        message.text = params.nick + ' is not kickable';
                        message.type = 'error';
                    }
                } else {
                    message.text = params.nick + ' is not online';
                    message.type = 'error';
                }

                showMessage(user.socket, message.text, message.type);
            }
        },
        ban : {
            params : ['nick'],
            optionalParams : ['reason'],
            permissions : [['ban', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };
                var targetUserMessage = "You've been banned: " + (params.reason ? ': ' + params.reason : '');

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
                    message.text = params.nick + ' is now banned';
                });
                const fail = then.catch(function () {
                    message.text = params.nick + ' is already banned';
                    message.type = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        banip : {
            params : ['nick', 'reason'],
            permissions : [['banip', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };
                const targetUser = findUserByAttribute(channel.online, 'nick', params.nick),
                      targetUserMessage = "You've been banned" + (params.reason ? ': ' + params.reason : '');
                
                if (targetUser) {
                    const then = dao.ban(channelName, targetUser.remote_addr, user.nick, params.reason).then(function () {
                        showMessage(targetUser.socket, targetUserMessage, 'error');
                        targetUser.socket.disconnect();

                        message.text = params.nick + ' is now IP banned';
                    });
                    const fail = then.catch(function () {
                        message.text = params.nick + ' is already IP banned';
                        message.type = 'error';
                    });
                    Promise.all([then, fail]).then(function () {
                        showMessage(user.socket, message.text, message.type);
                    });
                }
            }
        },
        unban : {
            params : ['nick'],
            permissions : [['unban', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                const then = dao.unban(channelName, params.nick).then(function () {
                    message.text = params.nick + ' is unbanned';
                });
                const fail = then.catch(function () {
                    message.text = params.nick + " isn't banned";
                    message.type = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        whitelist : {
            params : ['nick'],
            permissions : [['whitelist', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                const then = dao.find(params.nick).then(function (dbuser) {
                    dao.getChannelAtt(channelName, 'whitelist').then(function (whitelist) {
                        if (whitelist === undefined) {
                            whitelist = [];
                        }
                        if (whitelist.indexOf(user.nick) === -1) {
                            whitelist.push(params.nick);
                            dao.setChannelinfo(channelName, 'whitelist', whitelist).then(function () {
                                message.text = params.nick + ' is now whitelisted';
                            });
                        } else {
                            message.text = params.nick + ' is already whitelisted';
                            message.type = 'error';
                        }
                    });
                });
                const fail = then.catch(function () {
                    message = user.nick + ' is not registered';
                    message.type = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        unwhitelist : {
            params : ['nick'],
            permissions : [['unwhitelist', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                dao.getChannelAtt(channelName, 'whitelist').then(function (whitelist) {
                    if (whitelist === undefined) {
                        whitelist = [];
                    }
                    var index = whitelist.indexOf(params.nick);
                    if (index !== -1) {
                        whitelist.splice(index, 1);
                        dao.setChannelinfo(channelName, 'whitelist', whitelist).then(function () {
                            message.text = params.nick + ' has been unwhitelisted';
                        });
                    } else {
                        message.text = params.nick + ' isn\'t whitelisted';
                        message.type = 'error';
                    }
                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        delete : {
            params : ['nick'],
            permissions : [['delete', 'user']],
            handler : function (user, params) {
                var message = {
                    type: 'info'
                };

                const then = dao.unregister(params.nick).then(function () {
                    message = dbuser.nick + ' has been deleted.';
                })
                const fail = then.catch(function () {
                    message.text = params.nick + " isn't registered.";
                    message.type = 'error';
                });
                Promise.all([then, fail]).then(function () {
                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        global : {
            params : ['message'],
            permissions : [['send', 'globalMessage']],
            handler : function(user, params){
                if (params.message.length < 1000) {
                    io.emit('message',{
                        message : params.message,
                        messageType : 'general'
                    });
                } else {
                    showMessage(user.socket, 'message too long');
                }
            }
        },
        // TODO: copy this Promise.all algo
        find : {
            params : ['ip'],
            permissions : [['see', 'offlineUserIP']],
            handler : function (user, params) {
                var message,
                    messageType = 'info',
                    IP = params.ip;
                
                var required = [];
                function findAccounts (ip) {
                    required.push(dao.findip(ip).then(function (accounts) {
                        if (accounts && accounts.length) {
                            message.text = 'IP ' + ip + ' matched accounts: ' + accounts.join(', ');
                        } else {
                            message.text = 'No accounts matched this ip.';
                            message.type = 'error';
                        }
                    }));
                }

                if (IP.split('.').length !== 4) {//if paramter doesn't have 4 dots its a nick
                    var targetUser = findUserByAttribute(channel.online, 'nick', IP);
                    if (targetUser) {
                        findAccounts(targetUser.remote_addr);
                    } else {
                        required.push(dao.find(IP).then(function (dbuser) {
                            findAccounts(dbuser.remote_addr);
                        }).catch(function () {
                            message.text = 'No accounts matched this nick.';
                            message.type = 'error';
                        }));
                    }
                } else {
                    findAccounts(IP);
                }

                Promise.all(required).then(function () {
                    showMessage(user.socket, message.text, message.type);
                })
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
                Promise.all([
                    access.ensureRoleExists(rbac, params.role),
                    rbac.getPromise(params['role|permission'])
                ]).then(function (values) {
                    const role = values[0],
                          role_or_permission = values[1];

                    // TODO: copy this
                    Promise.resolve(new Promise(function (resolve, reject) {
                        var message = {
                            type: 'info'
                        };

                        if (role) {
                            if (role_or_permission) {
                                rbac.grant(role, role_or_permission, function (err, success) {

                                    if (success) {
                                        message.text = params.role + ' has been granted ' + params['role|permission'];
                                    } else {
                                        message.text = "can't grant " + params.role + ' ' + params['role|permission'];
                                    }

                                    resolve(message);
                                });
                            } else {
                                message.text = 'role|permission ' + params['role|permission'] + " doesn't exist";
                                resolve(message);
                            }
                        } else {
                            message.text = 'role for ' + params.nick + " doesn't exist";
                            resolve(message);
                        }
                    })).then(function (message) {
                        if (!message.hasOwnProperty('type')) {
                            message.type = 'info';
                        }
                        showMessage(user.socket, message.text, message.type);
                    });
                });
            }
        },
        // TODO: add revoking a role from another role while keeping the other permissions (one becomes many)
        revoke : {
            params : ['role', 'role|permission'],
            permissions : [['revoke', 'permission']],
            handler : function revoke(user, params) {
                Promise.all([
                    access.ensureRoleExists(rbac, params.role),
                    rbac.getPromise(params['role|permission'])
                ]).then(function (res) {
                    var message = {
                        type: 'info'
                    };
                    var user_role = res[0],
                        role_or_permission = res[1];

                    if (user_role) {
                        if (role_or_permission) {
                            rbac.revoke(user_role, role_or_permission, function callback_revoke (err, success) {
                                if (success) {
                                    message.text = 'revoked ';
                                } else {
                                    message.text = "couldn't revoke ";
                                }
                                message.text += params['role|permission'] + ' rights from ' + params.role;
                                // TODO: single endpoint
                                showMessage(user.socket, message.text, message.type);
                            });
                        } else {
                            message.text = 'role|permission ' + params['role|permission'] + " doesn't exist";
                        }
                    } else {
                        message.text = 'role for nick ' + params.role + " doesn't exist";
                    }

                    showMessage(user.socket, message.text, message.type);
                });
            }
        },
        can : {
            params : ['role', 'action', 'resource'],
            handler : function can(user, params) {
                rbac.canPromise(params.role, params.action, params.resource).then(function callback_can (err, can) {
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
        },
        // TODO: command for seeing all permissions
        /*
        perms : {
            ;
        },
        */
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
            params : ['nick', 'hat'],
            permissions : [['give', 'hat']],
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
                }).catch(function () {
                    showMessage(user.socket, 'That user isn\'t registered', 'error');
                });
            }
        },
        remove_hat : {
            params : ['nick', 'hat'],
            permissions : [['remove', 'hat']],
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
                }).catch(function () {
                    showMessage(user.socket, 'That user isn\'t registered', 'error');
                });
                
            }
        },
        hat : {
            params : ['hat'],
            permissions : [['set', 'hat']],
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
                }).catch(function () {
                    showMessage(user.socket, 'Must be registered to own a hat', 'error'); 
                });
            }
        },
        hatlist : {
            params : ['nick'],
            permissions : [['list', 'hat']],
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
                }).catch(function () {
                    showMessage(user.socket, params.nick + ' isn\'t registered', 'error');
                });
            }
        },
        afk : {
            params : ['message'],
            permissions : [['set', 'afk']],
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
            permissions : [['list', 'cursor']],
            handler : function (user) {
                var allCursors = dao.getCursors().lowercase;
                var b = allCursors.pop();
                showMessage(user.socket, 'Cursors available: ' + allCursors.join(", ") + 'and ' + b + '.');
            }
        },
        cursor : {
            params : ['cursor'],
            permissions : [['set', 'cursor']],
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
                }).catch(function () {
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
            permissions : [['set', 'flair']],
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
            }).catch(function () {
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
            }).catch(function () {
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
                rbac.canAll(user.role.name, command.permissions, callback_handleCommand);
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
            }).catch(function () {
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
                    }).catch(handleException);     
                } else {
                    showMessage(user.socket, errorMessage, 'error');
                }
            }
        });
        
        function joinChannel(userData, dbuser, channelData) {
            var i,
                onlineUsers = [];
            
            if (!userData) userData = {};
            
            function join(channelData, nick, role, hat, cursor) {
                user.nick = nick;
                user.role = role;
                user.token = dao.makeId();
                user.hat = hat && hat.current;
                user.cursor = cursor;
                tokens[user.nick] = user.token;

                access.ensureRoleExists(rbac, nick).then(function (user_role) {
                    rbac.grant(user_role, role_basic, function(){});
                    user.role = user_role;
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
                        token : user.token,
                        hats : hat
                    });
                    
                    roomEmit('joined', user.id, user.nick);
                    console.log('USER JOIN', nick, user.remote_addr);
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
            
            join(channelData, userData.nick, userData.role, userData.hat, userData.cursor);
        }
        
        function checkChannelStatus (joinData, dbuser) {
            var apiLink = 'http://check.getipintel.net/check.php?ip=' + user.remote_addr + '&contact=theorignalsandwich@gmail.com&flags=m';
            
            dao.banlist(channelName).then(function (nicks) {
                if (nicks.indexOf(user.nick) == -1 && nicks.indexOf(user.remote_addr) == -1) {
                    dao.getChannelinfo(channelName).then(function (channel) {
                        /*
                        if (dbuser && dbuser.role !== 0 && channel.roles[dbuser.nick]) {//assign channel role
                            dbuser.role = channel.roles[dbuser.nick];
                        }
                        */

                        function attemptJoin () {
                            if (channel.data.lock && channel.data.lock.value) {
                                if (dbuser && dbuser.nick) {
                                    joinChannel(joinData, dbuser, channel.data);
                                } else {
                                    socket.emit('locked');
                                }
                            } else {
                                joinChannel(joinData, dbuser, channel.data);
                            }
                        }

                        if (channel.data.proxy && channel.data.proxy.value) {
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
                            }).catch(checkChannelStatus);
                        } else {
                            delete joinData.nick;
                            checkChannelStatus(joinData);
                        }
                    }).catch(checkChannelStatus.bind(null, joinData));
                } else {
                    checkChannelStatus();
                } 
            } else {
                showMessage(socket, 'Only one socket connection allowed', 'error');
            }
        }
        
        socket.on('requestJoin', function (requestedData) {
            var message,
                messageType = 'info',
                joinData = {},
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

            const then = throttle.on(user.remote_addr + '-join', 3).then(function (notSpam) {
                if (notSpam) {
                    checkUserStatus(joinData);
                } else {
                    message.text = 'You are spamming, stop or you will be temporarily banned.';
                    throttle.warn(user.remote_addr + '-join');
                }
            });
            const fail = then.catch(function () {
                dao.ban(channelName, user.remote_addr, 'Throttle', 'Join spamming');
                message.text = 'You have been banned for spamming.';
                message.type = 'error';
            });
            Promise.all([then, fail]).then(function () {
                showMessage(socket, message, messageType);
                if (messageType === 'error') {
                    socket.disconnect();
                }
            })
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