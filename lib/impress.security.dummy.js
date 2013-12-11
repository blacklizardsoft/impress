(function(impress) {

  impress.security.user = impress.security.user.override(function(user) {
    user = this.inherited(user);
    return user;
  });

  impress.security.createDataStructures = function(callback) {
    if (callback) callback();
  }

  impress.security.dropDataStructures = function(callback) {
    if (callback) callback();
  }

  impress.security.emptyDataStructures = function(callback) {
    if (callback) callback();
  }

  // Register user, return true/false
  //   http post should contain "Email" and "Password" fields
  //   callback(err, user)
  //
  impress.security.register = function(req, res, callback) {
    impress.security.getUser(req.post.Email, function(err, user) {
      if (!user) {
        var uid = global.generateGUID();
        db.dummy.users[uid] = {
                                id: uid,
                                login: req.post.Email,
                                password: req.post.Password,
                                group: "users"
                              };
          var user = db.dummy.users[uid];
          if (user) {
            if (impress.sendPassword) impress.sendPassword(req.post.Email);
            impress.startSession(req, res);

            impress.users[user.id] = user;
            impress.sessions[req.impress.session].userId = user.id;
          }
          if (callback) callback(null, user);
      } else if (callback) callback(new Error("Email already registered"), user);
    });
  }

  // Get user record from database
  //   callback(user)
  //
  impress.security.getUser = function(login, callback) {
    async.filter(db.dummy.users,
                 function (item, callback) {
                   callback(item.login === login);
                 },
                 function(results){
                   if (results.length === 1){
                     callback(null, impress.security.user(results[0]));
                   }
                 });
  }

  // Get user record from database
  //   callback(user)
  //
  impress.security.getUserById = function(userId, callback) {
      callback(null, impress.security.user(db.dummy.users[userId]));
  }

  // Restore session if available
  //   callback(err, session)
  //
  impress.security.restorePersistentSession = function(sid, callback) {
    if (callback) callback();
  }

  impress.security.savePersistentSession = function(sid, callback) {
    if (callback) callback();
  }

  impress.security.deletePersistentSession = function(sid, callback) {
    if (callback) callback();
  };

} (global.impress = global.impress || {}));