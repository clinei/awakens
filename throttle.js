var THROTTLES = {};
module.exports = {
    on : function(id, max, resetTime) {
        return new Promise(function (resolve, reject) {
            var t = THROTTLES[id] = THROTTLES[id] || {
                count : 0
            };
            
            if (!max)  max = 10;
            if (!resetTime)  resetTime = 5000;
            
            if (t.count === 0) {
                setTimeout(function() {
                    if(THROTTLES[id].warn === undefined){
                        delete THROTTLES[id];
                    } else {
                        THROTTLES[id].count = 0;
                    }
                }, resetTime);
            }
             
            if (++t.count > max) {
                if(THROTTLES[id].warn >= 3){
                    reject();
                } else {
                    resolve(false);
                }
            } else {
                resolve(true);
            }
        });
    }, warn : function(id){
        THROTTLES[id].warn = ++THROTTLES[id].warn || 1;
        setTimeout(function() {
            --THROTTLES[id].warn;
            if(THROTTLES[id].warn === 0){
                delete THROTTLES[id].warn;
            }
        }, 1800000);   
    }
};