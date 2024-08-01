require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const { ObjectId } = require("mongodb");
const bodyParser = require('body-parser');
const twilio = require('twilio');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { connectToDb, getDb } = require('./db');

// Use environment variables
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const verifySid = process.env.TWILIO_VERIFY_SID;
const secretKey = process.env.JWT_SECRET_KEY;

const client = twilio(accountSid, authToken);

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Enable CORS

let db;

// Connect to the database and start the server
connectToDb((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  db = getDb();
  app.listen(3001, () => {
    console.log('App is listening on port 3001');
  });
});

// Middleware to authenticate tokens
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token is invalid' });
    req.user = user;
    next();
  });
}

// Endpoint to initiate OTP verification for signup
app.post('/signup', async (req, res) => {
    const { phoneNumber, username } = req.body;
  
    try {
      // Check if the phoneNumber already exists in the database
      const existingUser = await db.collection('users').findOne({ phoneNumber });
  
      if (existingUser) {
        // If user is already verified, send a message and do not send SMS
        if (existingUser.status === 'verified') {
          return res.status(400).send({ message: 'You have already signed up and are verified.' });
        }
  
        // If user exists but is not verified, resend OTP
        await client.verify.v2.services(verifySid)
          .verifications.create({ to: phoneNumber, channel: 'sms' });
  
        return res.status(200).send({ status: 'OTP sent again for signup' });
      }
  
      // If user does not exist, send OTP and store user data in the database
      await client.verify.v2.services(verifySid)
        .verifications.create({ to: phoneNumber, channel: 'sms' });
  
      await db.collection('users').updateOne(
        { phoneNumber },
        { $set: { phoneNumber, username, status: 'pending' } },
        { upsert: true }
      );
  
      res.status(200).send({ status: 'OTP sent for signup' });
    } catch (error) {
      console.error('Error during signup:', error);
      res.status(500).send({ error: error.message });
    }
});
  

// Endpoint to verify OTP and complete signup
app.post('/verify-signup', async (req, res) => {
  const { phoneNumber, otpCode } = req.body;

  try {
    const verification_check = await client.verify.v2
      .services(verifySid)
      .verificationChecks.create({ to: phoneNumber, code: otpCode });

    if (verification_check.status === 'approved') {
      const result = await db.collection('users').updateOne(
        { phoneNumber, status: 'pending' }, // Check for 'pending' status
        { $set: { status: 'verified' } }
      );

      if (result.matchedCount === 0) {
        return res.status(400).send({ error: 'User not registered or already verified' });
      }

      
      res.status(200).send({ status: 'Signup successful'});
    } else {
      res.status(400).send({ status: verification_check.status });
    }
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Endpoint to initiate OTP verification for login
app.post('/login', async (req, res) => {
  const { phoneNumber } = req.body;

  try {
    const user = await db.collection('users').findOne({ phoneNumber, status: 'verified' });

    if (user) {
      await client.verify.v2.services(verifySid)
        .verifications.create({ to: phoneNumber, channel: 'sms' });
      res.status(200).send({ status: 'OTP sent for login' });
    } else {
      res.status(400).send({ error: 'User not registered or not verified' });
    }
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});

// Endpoint to verify OTP and complete login
app.post('/verify-login', async (req, res) => {
  const { phoneNumber, otpCode } = req.body;

  try {
    const verification_check = await client.verify.v2
      .services(verifySid)
      .verificationChecks.create({ to: phoneNumber, code: otpCode });

    if (verification_check.status === 'approved') {
      const user = await db.collection('users').findOne({ phoneNumber, status: 'verified' });

      if (user) {
        const token = jwt.sign({ phoneNumber }, secretKey, { expiresIn: '9h' });
        res.status(200).send({ status: 'Login successful', token });
      } else {
        res.status(400).send({ error: 'User not registered or not verified' });
      }
    } else {
      res.status(400).send({ status: verification_check.status });
    }
  } catch (error) {
    res.status(500).send({ error: error.message });
  }
});
app.get("/user/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const phoneNumberFromToken = req.user.phoneNumber;

  try {
    // Ensure the phone number in the token matches a verified user
    const user = await db.collection('users').findOne({ _id: new ObjectId(id), phoneNumber: phoneNumberFromToken });

    if (!user) {
      return res.status(404).json({ message: "User not found or not authorized to access this information" });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error("Error retrieving user details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});


  app.post("/vendor/products", authenticateToken, async (req, res) => {
    const {
      productName,
      productDescription,
      productCategory,
      productSubcategory,
      price,
      stockAvailability,
      productPolicies,
      images,
      videos,
    } = req.body;
  
    const phoneNumberFromToken = req.user.phoneNumber;
  
    // Ensure the phone number in the token matches the phone number from the user
    try {
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      const formData = {
        productName,
        productDescription,
        productCategory,
        productSubcategory,
        price,
        stockAvailability,
        productPolicies,
        images,
        videos,
        userId: user._id
      };
  
      const collection = db.collection("products");
      const result = await collection.insertOne(formData);
      res.status(201).json({ message: "Product inserted successfully", productId: result.insertedId });
    } catch (error) {
      console.error("Error inserting product:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.get("/vendor/products", authenticateToken, async (req, res) => {
    try {
      const phoneNumberFromToken = req.user.phoneNumber;
      
      // Ensure the phone number in the token matches the phone number from the user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
      
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
      
      // Fetch products from the database
      const products = await db.collection('products').find({ userId: user._id }).toArray();
      res.status(200).json(products);
    } catch (error) {
      console.error("Error retrieving products:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.get("/vendor/products/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    
    try {
      const phoneNumberFromToken = req.user.phoneNumber;
      
      // Ensure the phone number in the token matches the phone number from the user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
      
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
      
      // Fetch the product from the database by ID
      const product = await db.collection('products').findOne({ _id: new ObjectId(id), userId: user._id });
      
      if (!product) {
        return res.status(404).json({ message: "Product not found" });
      }
      
      res.status(200).json(product);
    } catch (error) {
      console.error("Error retrieving product:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.delete("/vendor/products/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
  
    try {
      const phoneNumberFromToken = req.user.phoneNumber;
  
      // Ensure the phone number in the token matches the phone number from the user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      // Delete the product from the database by ID
      const result = await db.collection('products').deleteOne({ _id: new ObjectId(id), userId: user._id });
  
      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Product not found or not authorized to delete" });
      }
  
      res.status(200).json({ message: "Product deleted successfully" });
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.put("/vendor/products/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const phoneNumberFromToken = req.user.phoneNumber;
    const {
      productName,
      productDescription,
      productCategory,
      productSubcategory,
      price,
      stockAvailability,
      productPolicies,
      images,
      videos,
    } = req.body;
  
    try {
      // Ensure the phone number in the token matches a verified user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      // Find the product and ensure it belongs to the authenticated user
      const product = await db.collection('products').findOne({ _id: new ObjectId(id), userId: user._id });
  
      if (!product) {
        return res.status(404).json({ message: "Product not found or not authorized to edit" });
      }
  
      // Create an object with the existing product data
      const updatedProduct = {
        ...product, // Keep the existing data
        ...(productName !== undefined && { productName }),
        ...(productDescription !== undefined && { productDescription }),
        ...(productCategory !== undefined && { productCategory }),
        ...(productSubcategory !== undefined && { productSubcategory }),
        ...(price !== undefined && { price }),
        ...(stockAvailability !== undefined && { stockAvailability }),
        ...(productPolicies !== undefined && { productPolicies }),
        ...(images !== undefined && { images }),
        ...(videos !== undefined && { videos }),
      };
  
      const result = await db.collection('products').updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedProduct }
      );
  
      if (result.modifiedCount === 0) {
        return res.status(500).json({ message: "Product update failed" });
      }
  
      res.status(200).json({ message: "Product updated successfully" });
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  

  //servicePage
  app.post("/vendor/services", authenticateToken, async (req, res) => {
    const {
      serviceName,
      serviceCategory,
      location,
      description_ser,
      lowestAmount,
      highestAmount,
      selectedServices,
      selectedEventTypes,
      images,
      videos,
    } = req.body;
  
    const phoneNumberFromToken = req.user.phoneNumber;
  
    try {
      // Ensure the phone number in the token matches a verified user in the database
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      const formData = {
        serviceName,
        serviceCategory,
        location,
        description_ser,
        lowestAmount,
        highestAmount,
        selectedServices,
        selectedEventTypes,
        images,
        videos,
        userId: user._id // Use the user's ID from the database
      };
  
      const collection = db.collection("services");
  
      const result = await collection.insertOne(formData);
      res.status(201).json({ message: "Service inserted successfully", serviceId: result.insertedId });
    } catch (error) {
      console.error("Error inserting service:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.get("/vendor/services", authenticateToken, async (req, res) => {
    const phoneNumberFromToken = req.user.phoneNumber;
  
    try {
      // Ensure the phone number in the token matches a verified user in the database
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      // Fetch all services related to this user
      const services = await db.collection('services').find({ userId: user._id }).toArray();
  
      if (services.length === 0) {
        return res.status(404).json({ message: "No services found" });
      }
  
      res.status(200).json(services);
    } catch (error) {
      console.error("Error retrieving services:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.get("/vendor/services/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const phoneNumberFromToken = req.user.phoneNumber;
  
    try {
      // Ensure the phone number in the token matches a verified user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      // Fetch the service by ID and ensure it belongs to the authenticated user
      const service = await db.collection('services').findOne({ _id: new ObjectId(id), userId: user._id });
  
      if (!service) {
        return res.status(404).json({ message: "Service not found" });
      }
  
      res.status(200).json(service);
    } catch (error) {
      console.error("Error retrieving service:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app.put("/vendor/services/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const phoneNumberFromToken = req.user.phoneNumber;
    const {
      serviceName,
      serviceCategory,
      location,
      description_ser,
      lowestAmount,
      highestAmount,
      selectedServices,
      selectedEventTypes,
      images,
      videos,
    } = req.body;
  
    try {
      // Ensure the phone number in the token matches a verified user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      // Find the service and ensure it belongs to the authenticated user
      const service = await db.collection('services').findOne({ _id: new ObjectId(id), userId: user._id });
  
      if (!service) {
        return res.status(404).json({ message: "Service not found or not authorized to edit" });
      }
  
      // Create an object with the existing service data
      const updatedService = {
        ...service, // Keep the existing data
        ...(serviceName !== undefined && { serviceName }),
        ...(serviceCategory !== undefined && { serviceCategory }),
        ...(location !== undefined && { location }),
        ...(description_ser !== undefined && { description_ser }),
        ...(lowestAmount !== undefined && { lowestAmount }),
        ...(highestAmount !== undefined && { highestAmount }),
        ...(selectedServices !== undefined && { selectedServices }),
        ...(selectedEventTypes !== undefined && { selectedEventTypes }),
        ...(images !== undefined && { images }),
        ...(videos !== undefined && { videos }),
      };
  
      const result = await db.collection('services').updateOne(
        { _id: new ObjectId(id) },
        { $set: updatedService }
      );
  
      if (result.modifiedCount === 0) {
        return res.status(500).json({ message: "Service update failed" });
      }
  
      res.status(200).json({ message: "Service updated successfully" });
    } catch (error) {
      console.error("Error updating service:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  
 
  app.delete("/vendor/services/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const phoneNumberFromToken = req.user.phoneNumber;
  
    try {
      // Ensure the phone number in the token matches a verified user
      const user = await db.collection('users').findOne({ phoneNumber: phoneNumberFromToken, status: 'verified' });
  
      if (!user) {
        return res.status(400).json({ message: "User not registered or not verified" });
      }
  
      // Delete the service by ID if it belongs to the authenticated user
      const result = await db.collection('services').deleteOne({ _id: new ObjectId(id), userId: user._id });
  
      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "Service not found or not authorized to delete" });
      }
  
      res.status(200).json({ message: "Service deleted successfully" });
    } catch (error) {
      console.error("Error deleting service:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });
  