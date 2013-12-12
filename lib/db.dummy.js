(function(db) {

  db.drivers.dummy = {};
  db.dummy = {};

  // open([{
  //   name: "connectioName",
  //   url: "memcached://host:port",
  //   options: { poolSize:2000, ... }
  // },{...more connections...}],
  // function() {
  //   ...callback on all connections established...
  // });
  db.dummy.open = function(connection, callback) {
    db.connections.push(connection.name);
    db[connection.name] = connection;
    for (var i = 0; i < connection.collections.length; i++) {
      var collectionName = connection.collections[i];
      db.dummy[collectionName] = {};
    }
  }

} (global.db = global.db || {}));