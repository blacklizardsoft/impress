(function(impress) {

    impress.security.doSignIn = function(db, client, user, callback) {
        client.startSession();
        if (!client.application.users[user.Id]) client.application.users[user.Id] = user;
        client.application.sessions[client.session].userId = user.Id;
        client.application.sessions[client.session].login = user.Email;
        if (user.group) client.application.sessions[client.session].group = user.group;
        client.application.sessions[client.session].sessionModified = true;
        client.logged = true;
        if (user.lang) client.setCookie(client.application.config.projectx.localhost.i18n.cookieName, user.lang);
        if (client.fields.remember) {
            impress.security.generateToken(db, user.Id, function(err, token){
                if (!err) client.setCookie(client.application.config.projectx.localhost.cookies.tokenCookie, token);
                callback();
            });
        } else callback();
    }

    impress.security.signIn = function(db, client, callback) {
        var userEmail = impress.sanitizer.sanitize(client.fields.email),
            userPassword = impress.sanitizer.sanitize(client.fields.password);
        impress.security.getAccountByEmail(db, userEmail, function getAccountByEmailCallbackSignIn(err, user) {
            if (user) {
                if (user.emailVerified) {
                    var hash = impress.security.encryptPassword(userPassword, userEmail);
                    if (user.Password == hash) {
                        impress.security.doSignIn(db, client, user, function() { callback('success'); });
                    } else callback('incorrect');
                } else {
                    impress.security.sendVerificationEmail(db, user.Id, user.Email);
                    callback('verify');
                }
            } else callback('incorrect');
        });
    }

    impress.security.signInWithToken = function(db, client, token, callback) {
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

    impress.security.signInViaFb = function(db, client, callback) {
        var userEmail = impress.sanitizer.sanitize(client.fields.email);
        impress.security.getAccountByEmail(db, userEmail, function (err, user) {
            if (user) {
                impress.security.doSignIn(db, client, user, function() {
                    if (!user.emailVerified) {
                        user.emailVerified = 1;
                        db.update('accounts', user, function(err, affectedRows) {
                            callback('success');
                        });
                    } else callback('success');
                });
            } else callback('failed');
        });
    }

    impress.security.signInViaVk = function(db, client, callback) {
        var userEmail = impress.sanitizer.sanitize(client.fields.email);
        impress.security.getAccountByEmail(db, userEmail, function (err, user) {
            if (user) {
                if (user.emailVerified) {
                    impress.security.doSignIn(db, client, user, function() { callback('success'); });
                } else {
                    impress.security.sendVerificationEmail(db, user.Id, user.Email);
                    callback('verify');
                }
            } else callback('incorrect');
        });
    }

    impress.security.connectVk = function(db, client, callback) {
        var userEmail = impress.sanitizer.sanitize(client.fields.email),
            userPassword = impress.sanitizer.sanitize(client.fields.password);
        impress.security.getAccountByEmail(db, userEmail, function (err, user) {
            if (user) {
                var hash = impress.security.encryptPassword(userPassword, userEmail);
                if (user.Password == hash) {
                    user.vkUid = impress.sanitizer.sanitize(client.fields.vkUid);
                    db.update('accounts', user, function(err, affectedRows) {
                        if (user.emailVerified) {
                            impress.security.doSignIn(db, client, user, function() { callback('success'); });
                        } else {
                            impress.security.sendVerificationEmail(db, user.Id, user.Email);
                            callback('verify');
                        }
                    });
                } else callback('incorrect');
            } else callback('incorrect');
        });
    }

    var accounts = impress.require(impress.dir +'/model/accounts');
    var email = impress.require(impress.dir +'/model/email');

    impress.security.register = function(db, client, callback) {
        var userEmail = impress.sanitizer.sanitize(client.fields.email),
            userPassword = impress.sanitizer.sanitize(client.fields.password);
        impress.security.getAccountByEmail(db, userEmail, function (err, account) {
            if (!account) {
                var new_account = {
                    FirstName: '',
                    LastName: '',
                    Email: userEmail,
                    Password: impress.security.encryptPassword(userPassword, userEmail),
                    AccountTypeId: client.fields.type
                }
                if (client.fields.name) new_account.FirstName = impress.sanitizer.sanitize(client.fields.name);
                if (client.fields.vkUid) new_account.vkUid = impress.sanitizer.sanitize(client.fields.vkUid);
                if (client.fields.languageId) new_account.languageId = impress.sanitizer.sanitize(client.fields.languageId);
                accounts.createNewAccount(db, new_account, function (err, recordId) {
                    if (recordId > 0) {
                        impress.security.getAccountById(db, recordId, function (err, acc) {
                            impress.security.sendVerificationEmail(db, acc.Id, acc.Email);
                            if (callback) callback(err, acc);
                        });
                    } else if (callback) callback(err);
                });
            } else if (callback) {
                callback(new Error("Email already registered"), account);
            }
        });
    }
    impress.security.registerViaFb = function(db, client, callback) {
        var userEmail = impress.sanitizer.sanitize(client.fields.email),
            userName = impress.sanitizer.sanitize(client.fields.name);
        impress.security.getAccountByEmail(db, userEmail, function (err, account) {
            if (!account) {
                var userPassword = accounts.generatePassword(8);
                var new_account = {
                    FirstName: userName,
                    LastName: '',
                    Email: userEmail,
                    Password: impress.security.encryptPassword(userPassword, userEmail),
                    AccountTypeId: client.fields.type,
                    emailVerified: 1
                }
                accounts.createNewAccount(db, new_account, function (err, recordId) {
                    if (recordId > 0) {
                        impress.security.getAccountById(db, recordId, function (err, acc) {
                            impress.security.doSignIn(db, client, acc, function() {
                                if (callback) callback(err, acc);
                            });
                        });
                    } else if (callback) callback(err);
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
        db.queryRow(query_str, [email], function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountById = function(db, accountId, callback) {
        var query_str =
            'SELECT accounts.*, account_types.Group as `group`, languages.name as lang '+
            'FROM accounts, account_types, languages '+
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
        db.queryRow(query_str, [token], function (err, row) {
            if (callback) callback(err, row);
        });
    }

    impress.security.getAccountByVkUid = function(db, vkUid, callback) {
        var query_str =
            'SELECT accounts.*, account_types.Group as `group`, languages.name as lang '+
                'FROM accounts, account_types, languages '+
                'WHERE accounts.AccountTypeId = account_types.Id and accounts.languageId = languages.id '+
                'and accounts.vkUid = ?;';
        db.queryRow(query_str, [vkUid], function (err, row) {
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

    impress.security.encryptPassword = function(password, email) {
        return impress.crypto.createHash('md5').update(password).update(email).digest('hex');
    }

    impress.security.getCsrfToken = function(client) {
        var token = impress.uuid.v4();
        if (client.session) {
            if (client.application.sessions[client.session]._csrf)
                token = client.application.sessions[client.session]._csrf;
            else 
                client.application.sessions[client.session]._csrf = token;
        }
        return token;
    }

    impress.security.csrf = function(client) {
        var token = client.session ? client.application.sessions[client.session]._csrf : impress.uuid.v4();
        var val = csrfValue(client);
        if (val != token) return false;
        else return true;
    }

    function csrfValue(client) {
        return (client.fields && client.fields._csrf)
            || (client.query && client.query._csrf)
            || (client.req.headers['x-csrf-token']);
    }

} (global.impress = global.impress || {}));