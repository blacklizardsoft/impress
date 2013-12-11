(function(db) {

  var storage = {};
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
  db.dummy.open = function(connections, callback) {
    var cbCount = connections.length, cbIndex = 0;
    for (var i = 0; i < connections.length; i++) {
      var connection = storage;
      db.connections.push(connections[i].name);
      db[connections[i].name] = connection;
      cbIndex++;
      if (cbIndex>=cbCount && callback) callback(null);
    }
  }

} (global.db = global.db || {}));