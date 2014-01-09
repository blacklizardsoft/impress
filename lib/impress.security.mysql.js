(function(impress) {

    impress.security.signIn = function(db, client, callback) {
        impress.security.getAccountByEmail(db, client.fields.Login, function(err, user) {
            if (user && (user.Password == client.fields.Password)) {
                client.startSession();
                if (!impress.users[user.Id]) impress.users[user.Id] = user;
                impress.sessions[client.session].userId = user.Id;
                impress.sessions[client.session].login = user.Email;
                impress.security.getAccountTypeById(db, user.AccountTypeId, function(err, accType) {
                    if (accType) impress.sessions[client.session].group = accType.Group;
                });
                impress.sessions[client.session].sessionModified = true;
                client.logged = true;
                callback(true);
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
                            if (!impress.users[acc.Id]) impress.users[acc.Id] = acc;
                            impress.sessions[client.session].userId = acc.Id;
                            impress.sessions[client.session].login = acc.Email;

                            impress.security.getAccountTypeById(db, acc.AccountTypeId, function(err, accType) {
                                if (accType) impress.sessions[client.session].group = accType.Group;
                            });

                            impress.sessions[client.session].sessionModified = true;
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

    impress.security.getAccountTypeById = function(db, accTypeId, callback) {
        db.queryRow('SELECT account_types.* FROM account_types WHERE account_types.Id = ?;', [accTypeId],
        function (err, row) {
            if (callback) callback(err, row);
        });
    }

} (global.impress = global.impress || {}));