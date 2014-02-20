(function(impress) {

    impress.security.signIn = function(db, client, callback) {
        impress.security.getAccountByEmail(db, client.fields.Login, function getAccountByEmailCallbackSignIn(err, user) {
            if (user) {
                if (user.emailVerified) {
                    var hash = impress.security.encryptPassword(client.fields.Password);
                    if (user.Password == hash) {
                        client.startSession();
                        if (!client.application.users[user.Id]) client.application.users[user.Id] = user;
                        client.application.sessions[client.session].userId = user.Id;
                        client.application.sessions[client.session].login = user.Email;
                        if (user.group) client.application.sessions[client.session].group = user.group;
                        client.application.sessions[client.session].sessionModified = true;
                        client.logged = true;
                        if (user.lang) client.setCookie(client.application.config.projectx.localhost.i18n.cookieName, user.lang);
                        if (client.fields.Remember) {
                            impress.security.generateToken(db, user.Id, function(err, token){
                                if (!err) client.setCookie(client.application.config.projectx.localhost.cookies.tokenCookie, token);
                                callback('success');
                            });
                        } else callback('success');
                    } else callback('incorrect');
                } else {
                    impress.security.sendVerificationEmail(db, user.Id, user.Email);
                    callback('verify');
                }
            } else callback('incorrect');
        });
    }

    impress.security.signInWithToken = function(db, client, token, callback){
        impress.security.getAccountByToken(db, token, function(err, user) {
            if (user) {
                client.startSession();
                if (!client.application.users[user.Id]) client.application.users[user.Id] = user;
                client.application.sessions[client.session].userId = user.Id;
                client.application.sessions[client.session].login = user.Email;
                if (user.group) client.application.sessions[client.session].group = user.group;
                client.application.sessions[client.session].sessionModified = true;
                client.logged = true;
                if (user.lang) client.setCookie(client.application.config.projectx.localhost.i18n.cookieName, user.lang);
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
                      //Password: client.fields.Password,
                    Password: impress.security.encryptPassword(client.fields.Password),
                    AccountTypeId: client.fields.Type
                }
                accounts.createNewAccount(db, new_account, function (err, recordId) {
                    if (recordId > 0) {
                        impress.security.getAccountById(db, recordId, function (err, acc) {
                            //email.sendPassword(client.fields.Email);
                            impress.security.sendVerificationEmail(db, acc.Id, acc.Email);
                            /*client.startSession();
                            if (!client.application.users[acc.Id]) client.application.users[acc.Id] = acc;
                            client.application.sessions[client.session].userId = acc.Id;
                            client.application.sessions[client.session].login = acc.Email;
                            if (acc.group) client.application.sessions[client.session].group = acc.group;
                            client.application.sessions[client.session].sessionModified = true;
                            client.logged = true;*/

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
        var query_str =
            'SELECT accounts.*, account_types.Group as `group`, languages.name as lang '+
            'FROM accounts, account_types, languages '+
            'WHERE accounts.AccountTypeId = account_types.Id and accounts.languageId = languages.id '+
                'and accounts.Email = ?;';
        db.queryRow(query_str, [email],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountById = function(db, accountId, callback) {
        var query_str =
            'SELECT accounts.*, account_types.Group as `group`, languages.name as lang '+
            'FROM accounts, account_types '+
            'WHERE accounts.AccountTypeId = account_types.Id and accounts.languageId = languages.id '+
                'and accounts.Id = ?;';
        db.queryRow(query_str, [accountId], function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountByToken = function(db, token, callback) {
        var query_str =
            'SELECT accounts.*, account_types.Group as `group`, languages.name as lang '+
            'FROM accounts, account_types, languages, tokens '+
            'WHERE accounts.AccountTypeId = account_types.Id and accounts.languageId = languages.id '+
                'and accounts.Id = tokens.accountId and tokens.token = ?;';
        db.queryRow(query_str, [token],
            function (err, row) {
                if (callback) callback(err, row);
            }
        );
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

    impress.security.sendVerificationEmail = function(db, accountId, accEmail) {
        var token = impress.uuid.v4();
        var queryStr = 'SELECT * FROM verification_tokens WHERE verification_tokens.accountId = ?;';
        db.queryRow(queryStr, [accountId], function (err, row) {
            if (row) { //token exists
                row.token =  token;
                row.createDate = new Date();
                db.update('verification_tokens', row, function(err, affectedRows) {
                    email.sendVerification(accEmail, token);
                });
            }
            else { //new token
                var new_token = {
                    token: token,
                    accountId: accountId
                };
                db.insert('verification_tokens', new_token, function (err, recordId) {
                    email.sendVerification(accEmail, token);
                });
            }
            }
        );
    }

    impress.security.encryptPassword = function(password) {
        return impress.crypto.createHash('md5').update(password).digest('hex');
    }

} (global.impress = global.impress || {}));