require("dotenv").config();
var express = require("express");
var app = express();
const cors = require("cors");
const bodyParser = require("body-parser");
var sql = require("mssql");
const bcrypt = require("bcrypt");
const saltRounds = 10;


app.use(cors());

var config = {
  user: process.env.MSSQL_USER_LOGIN,
  password: process.env.MSSQL_USER_PASSWORD,
  server: process.env.MSSQL_SERVER_API,
  database: process.env.MSSQL_DATABASE_NAME,
  trustServerCertificate: true,
};

app.use(express.static("public"));
app.use(bodyParser.json());

//СПИСОК ПОЛЬЗОВАТЕЛЕЙ
app.get("/api/userlist", async (req, res) => {
  const pool = await sql.connect(config);
  let connection = new sql.ConnectionPool(config, function (err) {
    let request = new sql.Request(connection);
    try {
      pool
        .request()

        .query(`Select * FROM Users`)
        .then((result) => {
          res.status(200).json({ townlist: result.recordset });
        })
        .catch((error) => {
          console.error(error);
          res.status(500).json({ success: false, message: "Error on server" });
        })
        .finally(() => {
          connection.close();
        });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "Error on server" });
    }
  });
});

//Регистрация пользователя
app.post("/api/users/signup", async (req, res) => {
  const { login, password } = req.body;
  const hashedPassword = await bcrypt
    .hash(req.body.password, saltRounds)
    .then((hash) => {
      return hash;
    })
    .catch((err) => console.error(err.message));

  const pool = await sql.connect(config);
  let connection = new sql.ConnectionPool(config, function (err) {
    let request = new sql.Request(connection);
    try {
      pool
        .request()
        .input("login", sql.NVarChar, login)
        .input("password", sql.NVarChar(sql.MAX), hashedPassword)
        .query("INSERT INTO Users (login, password) VALUES (@login, @password)")
        .then((result) => {
          res
            .status(200)
            .json({ success: true, message: "Data added succesfully" });
        })
        .catch((error) => {
          console.error(error);
          res
            .status(500)
            .json({ success: false, message: "Error adding data" });
        })
        .finally(() => {
          connection.close();
        });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "Error adding data" });
    }
  });
});

//Авторизация пользователя
app.post("/api/users/signin", async (req, res) => {
  const { login, password } = req.body;

  const pool = await sql.connect(config);
  let connection = new sql.ConnectionPool(config, function (err) {
    let request = new sql.Request(connection);
    try {
      pool
        .request()
        .input("login", sql.NVarChar, login)
        .input("password", sql.NVarChar, password)
        .query(
          `SELECT * FROM Users
        WHERE login = @login`
        )
        .then((result) => {
          
          const checkPass = async () =>
            bcrypt.compare(
              password,
              result.recordset[0].password,
              function (err, result) {
                return result;
              }
            );

          if (checkPass) {
            
            res.status(200).json({
              id: result.recordset[0].id,
              login: result.recordset[0].login,
            });
          } else {
            res
              .status(401)
              .json({ success: false, message: "Password is not equal" });
          }
        })

        .catch((error) => {
          console.error(error);
          res.status(500).json({ success: false, message: "Server problem" });
        })

        .finally(() => {
          connection.close();
        });
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "Server problem (2)" });
    }
  });
});


var server = app.listen(8080, function () {
  console.log("Server is running..");
});
