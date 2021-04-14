var express = require('express');
var router = express.Router();

const admin_auth = require('../../middleware/admin.middleware')
const {contactus_validator} = require('../../validation/contactUs.validator');
const {validatorFunc} = require('../../helper/commonFunction.helper'); 

const {
  contactUs,
  getContactUsReq,
  getRequestDetail,
  closeContactRequest,
} = require('../controllers/contactUs.controller')

// router.post('/contactUs', contactus_validator, validatorFunc , contactUs)
router.get('/get-contactUs-list' , getContactUsReq)
router.get('/get-contactUs-details/:contactUs_id' , getRequestDetail)
router.put('/close-contactUs-request/:contactUs_id' , closeContactRequest)

module.exports = router;
