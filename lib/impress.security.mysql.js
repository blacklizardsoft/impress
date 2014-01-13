(function(impress) {

    impress.security.signIn = function(db, client, callback) {
        impress.security.getAccountByEmail(db, client.fields.Login, function(err, user) {
            if (user && (user.Password == client.fields.Password)) {
                client.startSession();
                if (!client.application.users[user.Id]) client.application.users[user.Id] = user;
                client.application.sessions[client.session].userId = user.Id;
                client.application.sessions[client.session].login = user.Email;
                impress.security.getAccountTypeById(db, user.AccountTypeId, function(err, accType) {
                    if (accType) client.application.sessions[client.session].group = accType.Group;
                });
                client.application.sessions[client.session].sessionModified = true;
                client.logged = true;
                impress.security.generateToken(db, user.Id, function(err, token){
                    if (!err) client.setCookie(client.application.config.projectx.localhost.cookies.tokenCookie, token);
                    callback(true);

                });
                //callback(true);
            } else callback(false);
        });
    }

    impress.security.signInWithToken = function(db, client, token, callback){
        impress.security.getAccountByToken(db, token, function(err, user) {
            if (user) {
                client.startSession();
                if (!client.application.users[user.Id]) client.application.users[user.Id] = user;
                client.application.sessions[client.session].userId = user.Id;
                client.application.sessions[client.session].login = user.Email;
                impress.security.getAccountTypeById(db, user.AccountTypeId, function(err, accType) {
                    if (accType) client.application.sessions[client.session].group = accType.Group;
                });
                client.application.sessions[client.session].sessionModified = true;
                client.logged = true;
                impress.security.generateToken(db, user.Id, function(err, token){
                    if (!err) client.setCookie(client.application.config.projectx.localhost.cookies.tokenCookie, token);
                    callback(true);

                });
            } else callback(false);
        });
    }

    var accounts = impress.require(impress.dir +'/model/accounts');
    var email = impress.require(impress.dir +'/model/email');

    impress.security.register = function(db, client, callback) {
        impress.security.getAccountByEmail(db, client.fields.Email, function (err, account) {
            if (!account) {
                var new_account = {
                    FirstName: '',
                    LastName: '',
                    Email: client.fields.Email,
                    Password: client.fields.Password,
                    AccountTypeId: client.fields.Type
                }
                accounts.createNewAccount(db, new_account, function (err, recordId) {
                    if (recordId > 0) {
                        impress.security.getAccountById(db, recordId, function (err, acc) {
                            email.sendPassword(client.fields.Email);
                            client.startSession();
                            if (!client.application.users[acc.Id]) client.application.users[acc.Id] = acc;
                            client.application.sessions[client.session].userId = acc.Id;
                            client.application.sessions[client.session].login = acc.Email;

                            impress.security.getAccountTypeById(db, acc.AccountTypeId, function(err, accType) {
                                if (accType) client.application.sessions[client.session].group = accType.Group;
                            });

                            client.application.sessions[client.session].sessionModified = true;
                            client.logged = true;

                            if (callback) callback(err, acc);
                        });
                    }
                });
            } else if (callback) {
                callback(new Error("Email already registered"), account);
            }
        });
    }

    impress.security.getAccountByEmail = function(db, email, callback) {
        db.queryRow('SELECT accounts.* FROM accounts WHERE accounts.Email = ?;', [email],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountById = function(db, accountId, callback) {
        db.queryRow('SELECT accounts.* FROM accounts WHERE accounts.Id = ?;', [accountId],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountByToken = function(db, token, callback) {
        db.queryRow('SELECT accounts.* FROM accounts, tokens WHERE tokens.token = ?;', [token],
            function (err, row) {
                if (callback) callback(err, row);
            }
        );
    }

    impress.security.getAccountTypeById = function(db, accTypeId, callback) {
        db.queryRow('SELECT account_types.* FROM account_types WHERE account_types.Id = ?;', [accTypeId],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.generateToken = function(db, accountID, callback){
        db.queryRow('SELECT * FROM tokens WHERE tokens.accountId = ?;', [accountID],
            function (err, row) {
                if (!err){
                    if (row){//token exists
                        row.token =  impress.uuid.v4();
                        var token = row.token;
                        db.update('tokens', row, function(err, affectedRows) {
                            callback(err, token);
                        });
                    }
                    else {//new token
                        var token = impress.uuid.v4();
                        var new_token = {
                            token: token,
                            accountId: accountID
                        };
                        db.insert('tokens', new_token, function (err, recordId) {
                            callback(err, token);
                        });
                    }
                } else callback(err);
            }
        );
    }

    impress.security.deleteToken = function(db, accountId, callback){
        db.delete('tokens', { accountId: accountId }, function(err, affectedRows) {
            callback(err);
        });
    }

} (global.impress = global.impress || {}));