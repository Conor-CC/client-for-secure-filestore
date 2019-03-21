var cryptico = require("cryptico");
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const ejs = require('ejs')
const express = require('express');
const bodyParser = require("body-parser");
const request = require("request");
var session = require('express-session');
const app = express();
const router = express.Router();

app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(bodyParser.json());
// your express configuration here
app.use(session({
	secret:'change_this',
	resave: false,
	saveUninitialized: false
}));


const httpServer = http.createServer(app);

router.use(function(req, res, next) {
    console.log(req.method, req.url);
    next();
});

router.get("/", function (req, res) {
    res.render("./login.ejs")
});

router.get("/dashboard", function (req, res) {
    res.render('./dashboard.ejs', {})
});

router.get("/createGroupPane", function (req, res) {
    res.render('./createGroupPane.ejs', {})
});

router.post("/register", function (req, res) {
  var symmetricKey = req.body.symmetric_key;
  var passPhrase = crypto.randomBytes(16).toString('base64');
  var bits = 1024;
  var privateKey = cryptico.generateRSAKey(passPhrase, bits);
  console.log("PRIVATE: " + JSON.stringify(privateKey));
  var publicKey = cryptico.publicKeyString(privateKey);
  console.log("PUBLIC: " + publicKey);
  var registration_data = {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: req.body.password,
    permissionLevel: 1,
    publicKey: publicKey
  };
  request.post({
    url: "http://localhost:8080/user/register/",
    headers: {'Content-Type':"application/json"},
    json: registration_data
  }, function () {
    res.redirect("/login");
  });
});

router.post("/createGroup", function (req, res) {
  var token = req.session.accessToken;
  var email = req.session.email;

  var encryptionResult;
  request.get({
    url: "http://localhost:8080/user/getPublicKeyById/",
    headers: {'Content-Type':"application/json",
              'x-access-token': token
    },
    json: {email: email}
  }, function (error, response, body) {
      var publicKey = body.publicKey;
      var symmetricKey = req.body.symmetricKey;
      encryptionResult = cryptico.encrypt(symmetricKey, publicKey);
      request.post({
            url: "http://localhost:8080/group/create/",
            headers: {'Content-Type':"application/json",
                      'x-access-token': token
            },
            json: {symmetricKey: encryptionResult}
          }, function(error, response, body) {
                console.log(body);
                res.status(201).send();
      });
  });


});

router.get("/addUserToMastersGroup", function (req, res) {
  var token = req.session.accessToken;
  request.get({
    url: "http://localhost:8080/group/findGroupById/",
    headers: {'Content-Type':"application/json",
              'x-access-token': token
    }
  }, function (error, response, body) {
    console.log(body);
    res.render("./listUserGroups.ejs", {groups: body});
  });
});

router.post("/addUserToMastersGroup", function (req, res) {
  var token = req.session.accessToken;
  var emailToAdd = req.body.email;
  var groupId = req.body.groupId;
  var symmetric = req.body.symmetricKey;
  request.get({
    url: "http://localhost:8080/user/getPublicKeyById/",
    headers: {'Content-Type':"application/json",
             'x-access-token':token
           },
    json: {email:emailToAdd}
  }, function (error, response, body) {
    console.log(body);
    var key = body.publicKey;
    var encryptionResult = cryptico.encrypt(symmetric, key);
    request.post({
      url: "http://localhost:8080/group/addUserToMastersGroup/",
      headers: {'Content-Type':"application/json",
               'x-access-token':token
             },
     json: {group_id:groupId, email:emailToAdd, new_user_encrypted_symmetric: encryptionResult}
    });
  });

});


// router.get("/login", function (req, res) {
//     res.render("./login.ejs")
// });

router.get("/getUserGroups", function (req, res) {
    var token = req.session.accessToken;
    request.get({
          url: "http://localhost:8080/group/getUserGroups/",
          headers: {'Content-Type':"application/json",
                   'x-access-token':token
                  }
          }, function(error, response, body) {
              res.render("./groupsList.ejs", {membership: body, userId: req.session.userId})
          });
});



router.get("/index", function (req, res) {
    res.render("./index.ejs")
});

router.post("/login", function (req, res) {
    // console.log(req.body);
    var login_data = {
      "email": req.body.email,
      "password": req.body.password
    }
    request.post({
          url: "http://localhost:8080/user/login/",
          header: {'Content-Type':"application/json"},
          json: login_data
        }, function(error, response, body) {
              req.session.userId = body.userId;
              req.session.accessToken = body.omaccessToken;
              req.session.email = body.email;
              res.redirect("/index")
    });
});

router.post("/generateKeyPair", function (req, res) {
    var symmetricKey = req.body.symmetric_key;
    var passPhrase = crypto.randomBytes(16).toString('base64');
    var bits = 1024;
    var privateKey = cryptico.generateRSAKey(passPhrase, bits);
    console.log("PRIVATE: " + JSON.stringify(privateKey));
    var publicKey = cryptico.publicKeyString(privateKey);
    console.log("PUBLIC: " + publicKey);
});

router.post("/encryptSymmetricKey", function (req, res) {
    var passedPublicKey = req.body.passedPublicKey;
    var symmetricKey = req.body.symmetricKey;
    var encryptionResult = cryptico.encrypt(symmetricKey, passedPublicKey);
    console.log("ENCRYPTED SYMM: " + JSON.stringify(encryptionResult));
});

app.use('/', router);
httpServer.listen(8081, '0.0.0.0');
