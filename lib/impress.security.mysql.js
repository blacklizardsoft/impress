(function(impress) {

    impress.security.signIn = function(req, res, callback) {
        impress.security.getAccountByEmail(req.post.Login, function(err, user) {
            if (user && (user.Password == req.post.Password)) {
                impress.startSession(req, res);
                if (!impress.users[user.Id]) impress.users[user.Id] = user;
                impress.sessions[req.impress.session].userId = user.Id;
                impress.sessions[req.impress.session].login = user.Email;
                if (user.group) impress.sessions[req.impress.session].group = user.group;
                impress.sessions[req.impress.session].sessionModified = true;
                req.impress.logged = true;
                callback(true);
            } else callback(false);
        });
    }

    impress.security.register = function(req, res, callback) {
        impress.security.getAccountByEmail(req.post.Email, function (err, account) {
            if (!account) {
                var new_account = {
                    FirstName: '',
                    LastName: '',
                    Email: req.post.Email,
                    Password: req.post.Password,
                    AccountTypeId: 1
                }
                db.impress.insert('accounts', new_account, function (err, recordId) {
                    if (recordId > 0) {
                        impress.security.getAccountById(recordId, function (err, acc) {
                            if (impress.sendPassword) impress.sendPassword(req.post.Email);

                            impress.startSession(req, res);
                            if (!impress.users[acc.Id]) impress.users[acc.Id] = acc;
                            impress.sessions[req.impress.session].userId = acc.Id;
                            impress.sessions[req.impress.session].login = acc.Email;
                            if (acc.group) impress.sessions[req.impress.session].group = acc.group;
                            impress.sessions[req.impress.session].sessionModified = true;
                            req.impress.logged = true;

                            if (callback) callback(err, acc);
                        });
                    }
                });
            } else if (callback) {
                callback(new Error("Email already registered"), account);
            }
        });
    }

    impress.security.getAccountByEmail = function(email, callback) {
        db.impress.queryRow('SELECT accounts.* FROM accounts WHERE accounts.Email = ?;', [email],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountById = function(accountId, callback) {
        db.impress.queryRow('SELECT accounts.* FROM accounts WHERE accounts.Id = ?;', [accountId],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

} (global.impress = global.impress || {}));