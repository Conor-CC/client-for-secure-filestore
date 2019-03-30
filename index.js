var cryptico = require("cryptico");
const AWS = require('aws-sdk');
const fs = require('fs');
const http = require('http');
const ejs = require('ejs')
const express = require('express');
const bodyParser = require("body-parser");
const request = require("request");
var session = require('express-session');
const app = express();
const router = express.Router();
var multer = require('multer');
var upload = multer({ dest: '../drive/' });
const crypto = require('crypto');
var cp = require('child_process'), assert = require('assert');
const path = require('path');
const config = require('./config.json');

//configuring the AWS environment
AWS.config.update({
    accessKeyId: config.accessId,
    secretAccessKey: config.secretKey
});

var s3 = new AWS.S3();


const networkDrive = "home/conor/Desktop/NetworkDrive";


const encrypt = (data, pubKey)  => {
    var buffer = Buffer.from(data);
    var encryptedData = crypto.publicEncrypt(pubKey, buffer);
    return encryptedData.toString('base64')
}

const decrypt = (data, privKey) => {
    var buffer = Buffer.from(data, "base64");
    var decryptedData = crypto.privateDecrypt(privKey, buffer);
    return decryptedData.toString('utf8')
}


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
  var registration_data = {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: req.body.password,
    permissionLevel: 1,
    publicKey: ''
  };
  var privateKey, publicKey;
  publicKey = '';
  cp.exec('openssl genrsa 2048', function(err, stdout, stderr) {
    assert.ok(!err);
    privateKey = stdout;
    console.log(privateKey);
    makepub = cp.spawn('openssl', ['rsa', '-pubout']);
    makepub.on('exit', function(code) {
      assert.equal(code, 0);
      console.log(publicKey);

      registration_data.publicKey = publicKey;
      request.post({
        url: "http://localhost:8080/user/register/",
        headers: {'Content-Type':"application/json"},
        json: registration_data
      }, function () {
        const storeData = (data, path) => {
          try {
            fs.writeFileSync(path, JSON.stringify(data))
          } catch (err) {
            console.error(err)
          }
        }
        var local_users = JSON.parse(fs.readFileSync('user_keys.json', 'utf-8'));
        var data = {email:registration_data.email, publicKey: publicKey, privateKey: privateKey}
        local_users.push(data);
        storeData(local_users, 'user_keys.json');
        console.log("New User:\n" + data);
        res.redirect("/");
      });


    });
    makepub.stdout.on('data', function(data) {
      publicKey += data;
      registration_data.publicKey = registration_data.publicKey + data;
    });
    makepub.stdout.setEncoding('ascii');
    makepub.stdin.write(privateKey);
    makepub.stdin.end();
    console.log("PUB: " + registration_data.publicKey);

  });
});

router.post("/createGroup", function (req, res) {
  var token = req.session.accessToken;
  var email = req.session.email;
  var groupName = req.body.groupName;
  var encryptionResult;
  request.get({
    url: "http://localhost:8080/user/getPublicKeyById/",
    headers: {'Content-Type':"application/json",
              'x-access-token': token
    },
    json: {email: email}
  }, function (error, response, body) {
      var publicKey = body.publicKey;
      var symmetricKey = crypto.randomBytes(16).toString('base64');
      console.log("Symmetric: " + symmetricKey);
      encryptionResult = encrypt(symmetricKey, req.session.publicKey);
      request.post({
            url: "http://localhost:8080/group/create/",
            headers: {'Content-Type':"application/json",
                      'x-access-token': token
            },
            json: {symmetricKey: encryptionResult, groupName: groupName}
          }, function(error, response, body) {
                //console.log(body);
                res.redirect("/index")
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
    res.render("./listUserGroups.ejs", {groups: body});
  });
});

router.post("/addUserToMastersGroup", function (req, res) {
  var token = req.session.accessToken;
  var emailToAdd = req.body.email;
  var groupId = req.body.groupId;
  var symmetric = req.body.symmetricKey;
  request.get({
    url: "http://localhost:8080/group/findGroupById/",
    headers: {
      "x-access-token": token
    }
  }, function (error, response, body) {
      var obj = JSON.parse(body);
      console.log(obj[0]);
      var owner = -1;
      var group = {};
      var encrypted_symmetric = "";
      var privateKey = "";
      if (!error) {
        var i = 0;
        for (i = 0; i < obj.length; i++) {
          if (groupId == obj[i]._id) {
            group = obj[i];
            console.log("Group: " + group);
            owner = obj[i].ownerId;
            i = obj.length;
          }
        }
        console.log(group);
        var members = group.members;
        console.log(JSON.stringify(members));
        for (i = 0; i < members.length; i++) {
          if (members[i].user_id === owner) {
            encrypted_symmetric = members[i].encrypted_symmetric;
          }
        }
        var local_data = JSON.parse(fs.readFileSync('user_keys.json'));
        for (i = 0; i < local_data.length; i++) {
          if (req.session.email === local_data[i].email) {
            privateKey = local_data[i].privateKey;
          }
        }
        console.log(privateKey);
        console.log("Enc-symm: " + encrypted_symmetric);
        var decryptedSymmetric = decrypt(encrypted_symmetric, privateKey);
        console.log("Decrypted Symm:" + decryptedSymmetric);
        request.get({
          url: "http://localhost:8080/user/getPublicKeyById/",
          headers: {'Content-Type':"application/json",
                   'x-access-token':token
                 },
          json: {email:emailToAdd}
        }, function (error, response, body) {
          // console.log(body);
          var key = body.publicKey;
          var encryptionResult = encrypt(decryptedSymmetric, key);
          request.post({
            url: "http://localhost:8080/group/addUserToMastersGroup/",
            headers: {'Content-Type':"application/json",
                     'x-access-token':token
                   },
           json: {group_id:groupId, email:emailToAdd, new_user_encrypted_symmetric: encryptionResult}
         }, function () {
           res.redirect("/index")
         });
        });
      }
  });


});


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
    if (req.session.userId) {
      res.render("./index.ejs")
    }
    else {
      res.redirect("/")
    }
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
              req.session.publicKey = body.publicKey;
              res.redirect("/index")
    });
});

router.post("/uploadFile", upload.single('fileyboi'), function (req, res) {
    var token = req.session.accessToken;
    //Get user encrypted symmetric key from group members data
    console.log(req.body);
    var obj = JSON.parse(req.body.groupData);
    var members = obj.members;
    var encrypted_symmetric = "";
    var i = 0;
    for (i = 0; i < members.length; i++) {
      if (req.session.email == members[i].email) {
        encrypted_symmetric = members[i].encrypted_symmetric;
      }
    }
    console.log(encrypted_symmetric);
    //Decrypt user encypted symmetric with user pk
    var privateKey = '';
    var local_data = JSON.parse(fs.readFileSync('user_keys.json'));
    for (i = 0; i < local_data.length; i++) {
      if (req.session.email === local_data[i].email) {
        privateKey = local_data[i].privateKey;
      }
    }
    decryptedSymmetric = decrypt(encrypted_symmetric, privateKey);
    //encrypt file with symmetric and crypto.encrypt(buffer, key)


    var buffer = fs.readFileSync(req.file.path, 'utf-8');
    var cipher = crypto.createCipher('aes256', decryptedSymmetric);
    var ciphered = cipher.update(Buffer.from(buffer), 'utf8', 'hex');
    ciphered += cipher.final('hex');

    var name = req.file.path.split('/');
    name = name[name.length - 1];



    var filePath = "./tmp/" + name;
    //configuring parameters
    var params = {
      Bucket: 'node-keystore-bucket',
      Body : ciphered,
      Key : "folder/"+name
    };
    console.log("Parameters: " + JSON.stringify(params));
    s3.upload(params, function (err, data) {
      //handle error
      if (err) {
        console.log("Error", err);
      }

      //success
      if (data) {
        console.log("Uploaded in:", data.Location);
        request.patch({
          url: "http://localhost:8080/group/mediaLinks/",
          headers: { "Content-Type":"application/json",
                     "Authorization": token
          },
          json: {groupId: obj._id, link: ("folder/" + name)}
        }, function () {
          console.log("Encrypted write success! Stored in folder/" + name);
          res.redirect("/index");
        });
        //Now simulate decryption for testing
      }
    });
});

router.post("/decryptFile", function (req, res) {
    // Parse file URL/URI, get file
    var url_path = req.body.url;
    console.log(req.body);

    var name = url_path.split("/")
    name = name[name.length - 1]


    s3.getObject(
      { Bucket: "node-keystore-bucket", Key: ("folder/" + name) },
      function (error, data) {
        if (error != null) {
          console.log("Failed to retrieve an object: " + error);
        } else {
          console.log("Loaded " + data.ContentLength + " bytes");
          // do something with data.Body
          console.log("Oi lad heres the object there now hai: " + data.Body.toString());
          var encrypted_object = data.Body.toString();
          //Below will be a get request to cloud in future!!!
          // (For now just get from local file store)
          //var encryptedFile = fs.readFileSync(url_path, 'utf-8')


          // Get users encrypted symmetric from group
          console.log(req.body);
          var obj = JSON.parse(req.body.groupData);
          var members = obj.members;
          var encrypted_symmetric = "";
          var i = 0;
          for (i = 0; i < members.length; i++) {
            if (req.session.email == members[i].email) {
              encrypted_symmetric = members[i].encrypted_symmetric;
            }
          }
          console.log(encrypted_symmetric);
          //Decrypt user encypted symmetric with user pk
          var privateKey = '';
          var local_data = JSON.parse(fs.readFileSync('user_keys.json'));
          for (i = 0; i < local_data.length; i++) {
            if (req.session.email === local_data[i].email) {
              privateKey = local_data[i].privateKey;
            }
          }
          console.log("ENC SYM: " + encrypted_symmetric);
          console.log("Priv: " + privateKey);
          decryptedSymmetric = decrypt(encrypted_symmetric, privateKey);
          console.log("Symmetric decrypted! " + decryptedSymmetric);
          //Decrypt subsequently decrypt file with symmetric
          var decipher = crypto.createDecipher('aes256', decryptedSymmetric);
          var deciphered = decipher.update(encrypted_object, 'hex', 'utf8');
          deciphered += decipher.final();
        }
      }
    );

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
