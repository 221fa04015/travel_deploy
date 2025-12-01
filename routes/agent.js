const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');  // User model used for both users and agents
const { protect } = require('../middleware/auth');
require('dotenv').config();  // Load environment variables

const router = express.Router();

router.post('/register', async (req, res) => {
  const { agentname, agentemail, agentpassword, agentid, agency, phone } = req.body;

  try {
      // Check if the agent already exists in the database (use email to check uniqueness)
      const existingUser = await User.findOne({ email: agentemail });
      if (existingUser) {
          return res.status(400).send('Agent with this email already exists');
      }

      // Create a new agent instance and save it to the database
      const newUser = new User({
          username: agentname,  // Use 'username' field from the model
          email: agentemail,    // Use 'email' field from the model
          password: agentpassword,  // Use 'password' field from the model
          agentId: agentid,     // Use 'agentId' field from the model
          agency: agency,       // Set agency field
          phone: phone,         // Set phone field
          role: 'agent'         // Set role as 'agent'
      });

      // Save the agent to the database
      await newUser.save();

      // Sign the JWT token with the agent's ID
      const token = jwt.sign(
          { id: newUser._id, role: newUser.role }, // Include agent ID and role in the token
          process.env.JWT_SECRET,
          { expiresIn: '1h' } // Token expires in 1 hour
      );

      // Set the token in an HTTP-only cookie
      res.cookie('token', token, { httpOnly: true });

      // Redirect to agent dashboard after successful registration
      res.redirect('/agent/dashboard');
  } catch (err) {
      console.error(err);
      res.status(500).send('Error registering agent');
  }
});

// Protected routes for agent pages
router.get('/dashboard', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_dashboard', { agentname: req.user.username });
});

router.get('/clients', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_clients', { agentname: req.user.username });
});

router.get('/services', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_services', { agentname: req.user.username });
});

router.get('/offers', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_offers', { agentname: req.user.username });
});

router.get('/packages', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_packages', { agentname: req.user.username });
});

router.get('/profile', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_profile', { agentname: req.user.username });
});

router.get('/history', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent_history', { agentname: req.user.username });
});

// POST route to update agent profile
router.post('/profile', protect, async (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }

  const { agentname, agentemail, agentid, phone, agency, bio } = req.body;

  try {
    // Update the agent in the database
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      {
        username: agentname,
        email: agentemail,
        agentId: agentid,
        phone,
        agency,
        bio
      },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      return res.status(404).send('Agent not found');
    }

    // Update the session with new user data
    req.user = updatedUser;

    // Redirect back to profile page with success message or just render
    res.render('agent_profile', {
      agentname: updatedUser.username,
      agentemail: updatedUser.email,
      agentid: updatedUser.agentId,
      phone: updatedUser.phone,
      agency: updatedUser.agency,
      bio: updatedUser.bio,
      successMessage: 'Profile updated successfully'
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating profile');
  }
});

// POST route to change agent password
router.post('/change-password', protect, async (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }

  const { currentPassword, newPassword } = req.body;

  try {
    // Check if current password is correct
    const isMatch = await req.user.matchPassword(currentPassword);
    if (!isMatch) {
      return res.render('agent_profile', {
        agentname: req.user.username,
        agentemail: req.user.email,
        agentid: req.user.agentId,
        phone: req.user.phone,
        agency: req.user.agency,
        bio: req.user.bio,
        errorMessage: 'Current password is incorrect'
      });
    }

    // Update password
    req.user.password = newPassword;
    await req.user.save();

    res.render('agent_profile', {
      agentname: req.user.username,
      agentemail: req.user.email,
      agentid: req.user.agentId,
      phone: req.user.phone,
      agency: req.user.agency,
      bio: req.user.bio,
      successMessage: 'Password changed successfully'
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error changing password');
  }
});

// GET route for manage privacy
router.get('/privacy', protect, (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }
  res.render('agent/privacy', { agentname: req.user.username });
});

// POST route to delete agent account
router.post('/delete-account', protect, async (req, res) => {
  if (req.user.role !== 'agent') {
    return res.status(403).send('Forbidden');
  }

  try {
    await User.findByIdAndDelete(req.user._id);
    res.clearCookie('token');
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting account');
  }
});

module.exports = router;
