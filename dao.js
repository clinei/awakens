var _ = require('underscore');
var $ = require('jquery-deferred');
var mysql = require('mysql');
var bcrypt = require('bcrypt-nodejs');
var fs = require('fs');

try {
    var file = fs.readFileSync('./conf/settings.json');
    settings = JSON.parse(file.toString());
    handleDisconnect(settings);
} catch (e) {
    throw new Error('Invalid settings: /conf/settings.json invalid or does not exist');
}

var db;
function handleDisconnect(db_config) {
    db = mysql.createConnection(db_config);
    //check for error on connect
    db.connect(function (err) {
        if (err) {
            console.log(err);
        }
    });

    db.on('error', function (err) {
        console.log('db error', err);
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            handleDisconnect();
        } else {
            throw err;
        }
    });
}

function ucwords(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

module.exports = {
    encrypt : function(password){
        var defer = $.Deferred();
        bcrypt.genSalt(10, function(err, salt){
            bcrypt.hash(password, salt, null, function(err, hash){
                defer.resolve(hash).promise();
            });
        });
        return defer;
    },
    register : function (nick, password, ip) {
        var defer = $.Deferred();
        var sql = "INSERT INTO `awakens`.`users`(`nick`,`password`,`remote_addr`,`role`) VALUES(?,?,?,?)";
        bcrypt.genSalt(10, function (err, salt) {
            bcrypt.hash(password, salt, null, function (err, hash) {
                db.query(sql, [nick, hash, ip, 4], function (err, rows, fields) {
                    if (err) {
                        defer.reject(err);
                    } else {
                        defer.resolve().promise();
                    }
                });
            });
        });
        return defer;
    },
    login : function (nick, password) {
        var defer = $.Deferred();
        var sql = "SELECT * FROM `users` WHERE `nick` = ?";
        db.query(sql, nick, function (err, rows, fields) {
            if (rows && rows.length) {
                bcrypt.compare(password, rows[0].password, function (err, res) {//check if password is correct
                    defer.resolve(res, rows[0]).promise();
                });
            } else {//not an account
                defer.reject();
            }
        });
        return defer;
    },
    find : function (nick) {
        var defer = $.Deferred();
        var sql = "SELECT * FROM `users` WHERE `nick` = ?";
        db.query(sql, nick, function (err, rows, fields) {
            if (rows && rows.length) {
                defer.resolve(rows[0]).promise();
            } else {
                defer.reject();
            }
        });
        return defer;
    },
    getChannelinfo : function (channelName) {
        var defer = $.Deferred();
        var sql = "SELECT * FROM `channel_info` WHERE `channelName` = ?";
        db.query(sql, channelName, function (err, rows, fields) {
            if (rows && rows.length) {
                try {
                    defer.resolve(JSON.parse(rows[0].roles), JSON.parse(rows[0].data)).promise();
                } catch (err) {
                    defer.reject(err);
                }
            } else {
                db.query("INSERT INTO `awakens`.`channel_info` (`channelName`, `roles`, `data`) VALUES (?, '{}', '{}');", channelName, function (err, rows, fields) {
                    defer.resolve({}, {}).promise();
                });
            }
        });
        return defer;
    },
    setChannelinfo : function(channelName, att, value){
        var defer = $.Deferred();
        var sql = "UPDATE `awakens`.`channel_info` SET `data` = ? WHERE `channel_info`.`channelName` = ?";
        this.getChannelinfo(channelName).then(function(roles, channelData){
            channelData[att] = value;
            db.query(sql, [JSON.stringify(channelData), channelName], function(err, rows, fields){
                if (err) {
                    defer.reject(err);
                } else {
                    defer.resolve().promise();   
                }
            });
        }).fail(function () {
            channelData = {};
            channelData[att] = value;
            db.query("INSERT INTO `awakens`.`channel_info` (`channelName`, `roles`, `data`) VALUES (?, '{}', ?);", [channelName, JSON.stringify(channelData)]);
            defer.resolve().promise();   
        });
        return defer;
    },
    setUserinfo : function (nick, att, value) {
        var defer = $.Deferred();
        var sql = "UPDATE `awakens`.`users` SET ?? = ? WHERE `nick` = ?";
        db.query(sql, [att, value, nick], function (err, rows, fields) {
            if (err) {
                defer.reject(err);
            } else {
                defer.resolve().promise();
            }
        });
        return defer;
    },
    banlist : function(channelName){
        var defer = $.Deferred();
        var sql = "SELECT * FROM `channel_banned` WHERE `channelName` = ?;"
        db.query(sql, channelName, function (err, rows, fields) {
            var banlist = [],
                rows;
            
            if(rows && rows.length){
                rows = JSON.parse(rows[0].banned);
                for(var i = 0; i < rows.length; i++){
                    banlist.push(rows[i].nick);
                }
                defer.resolve(banlist, rows).promise();
            } else {
                db.query("INSERT INTO `awakens`.`channel_banned` (`channelName`, `banned`) VALUES (?, '[]');", channelName);
                defer.resolve([]).promise();
            }
        });
        return defer;
    },
    ban : function(channelName, nick, bannedBy, reason){
        var defer = $.Deferred();
        var sql = "UPDATE `awakens`.`channel_banned` SET `banned` = ? WHERE `channelName` = ?;";
        this.banlist(channelName).then(function(banlist, banData){            
            if (banlist.indexOf(nick) === -1) {
                banData.push({
                    nick : nick,
                    bannedBy : bannedBy, 
                    reason : reason
                });
                db.query(sql, [JSON.stringify(banData), channelName],function(err, rows, fields){
                    defer.resolve().promise();
                });
            } else {
                defer.reject();
            }
        });
        return defer;
    },
    getNick : function () {
        var nouns = ["alien", "apparition", "bat", "blood", "bogeyman", "boogeyman", "boo", "bone", "cadaver", "casket", "cauldron", "cemetery", "cobweb", "coffin", "corpse", "crypt", "darkness", "dead", "demon", "devil", "death", "eyeball", "fangs", "fear", "gastly", "gengar", "ghost", "ghoul", "goblin", "grave", "gravestone", "grim", "grimreaper", "gruesome", "haunter", "headstone", "hobgoblin", "hocuspocus", "howl", "jack-o-lantern", "mausoleum", "midnight", "monster", "moon", "mummy", "night", "nightmare", "ogre", "phantasm", "phantom", "poltergeist", "pumpkin", "scarecrow", "scream", "shadow", "skeleton", "skull", "specter", "spider", "spine", "spirit", "spook", "tarantula", "tomb", "tombstone", "troll", "vampire", "werewolf", "witch", "witchcraft", "wraith", "zombie"];
        var adjectives = ["bloodcurdling", "chilling", "creepy", "dark", "devilish", "dreadful", "eerie", "evil", "frightening", "frightful", "ghastly", "ghostly", "ghoulish", "gory", "grisly", "hair-raising", "haunted", "horrible", "macabre", "morbid", "mysterious", "otherworldly", "repulsive", "revolting", "scary", "shadowy", "shocking", "spine-chilling", "spooky", "spoopy", "startling", "supernatural", "terrible", "unearthly", "unnerving", "wicked"];
        return ucwords(_.sample(adjectives)) + ucwords(_.sample(nouns));
    },
    makeId : function () {
        var text = "";
        var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        for (var i=0; i < 15; i++ )
            text += possible.charAt(Math.floor(Math.random() * possible.length));

        return text;
    }
}