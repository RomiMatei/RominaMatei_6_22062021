const express = require("express");
const mongoose = require("mongoose");
const path = require("path");
const mongoSanitize = require("express-mongo-sanitize");
// Searches for any keys in objects that begin with a $ sign or contain a . from req.body,
//  req.query or req.params and either removes such keys and data or replaces the prohibited
//   characters with another allowed character.

const helmet = require("helmet");
//Sets security-related HTTP response headers to protect against some well-known web vulnerabilities.

const xssClean = require("xss-clean");
//  Sanitizes user input coming from POST request body (req.body), GET request query (req.query) and URL parameters (req.params)

const hpp = require("hpp");
// Puts the array parameters in req.query and/or req.body asides and just selects the last
// parameter value to avoid HTTP Parameter Pollution attacks.

const rateLimit = require("express-rate-limit");
// Used to limit IP addresses from making repeated requests to API endpoints.
// An example would be to rate limit an endpoint that is responsible for sending password reset emails,
//  which can incur additional fees.

let Ddos = require("ddos");
let ddos = new Ddos({ burst: 10, limit: 15 });

const saucesRoutes = require("./routes/sauces");
const userRoutes = require("./routes/user");
require("dotenv").config();

mongoose
  .connect(
    "mongodb+srv://" +
      process.env.UserDB +
      ":" +
      process.env.PassDB +
      "@" +
      process.env.DbAddress,
    { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true }
  )
  .then(() => console.log("Connexion à MongoDB réussie !"))
  .catch(() => console.log("Connexion à MongoDB échouée !"));

const app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content, Accept, Content-Type, Authorization"
  );
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, PATCH, OPTIONS"
  );
  next();
});

app.use(express.json());

app.use("/api/sauces", saucesRoutes);
app.use("/api/auth", userRoutes);
app.use("/images", express.static(path.join(__dirname, "images")));

// Using helmet middleware
app.use(helmet());

// Protect against XSS attacks, should come before any routes
app.use(xssClean());

// Protect against HPP, should come before any routes
app.use(hpp());

// Remove all keys containing prohibited characters
app.use(mongoSanitize());

// Restrict all routes to only 100 requests per IP address every 1o minutes
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 100, // 100 requests per IP
});
app.use(limiter);

app.use(ddos.express);

module.exports = app;
