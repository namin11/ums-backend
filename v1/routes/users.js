var express = require('express');
var router = express.Router();
const { body } = require('express-validator');
var multer = require('multer');


var storage = multer.diskStorage({
  destination: (req, files, cb) => {
    if (files.fieldname == `exam`) { cb(null, '../../public/media/exam'); }

  },
  filename: (req, file, cb) => {
    if (file.originalname.indexOf(' ')) {
      file.originalname = file.originalname.replace(/ /g, '_');
    }
    var ext = file.originalname.split('.');
    var today = new Date();
    var dd = today.getDate();
    var mm = today.getMonth() + 1; //January is 0!

    var yyyy = today.getFullYear();
    if (dd < 10) {
      dd = '0' + dd;
    }
    if (mm < 10) {
      mm = '0' + mm;
    }
    var today = dd + '-' + mm + '-' + yyyy;
    cb(null, req.session.userDetails._id + '_' + file.fieldname + '-' + today + '.' + ext[1]);
  }
});
const fileFilter = (req, file, cb) => {

  if (
    file.mimetype === "image/png" ||
    file.mimetype === "image/jpg" ||
    file.mimetype === "image/jpeg" ||
    file.mimetype === "application/pdf"
  ) {

    cb(null, true);
  } else {

    req.errorMessage = "File format should be PNG,JPG,JPEG";
    cb(null, false);
    //cb(new Error("File format should be PNG,JPG,JPEG"), false); // if validation failed then generate error
  }
};


const {authenticate, adminAuthenticate, facultyAuthenticate} = require('../../middleware/authenticate');
const { user_validator,
  login_validator,
  changePassword_validator,
  forgotPassword_validator,
  socialLogin_validator,
  restPassword_validator,
  update_validator
 } = require('../../validation/user.middleware')

const { add_contactus_validator } = require('../../validation/contactUs.validator');

const {validatorFunc, validatorFuncRender} = require('../../helper/commonFunction.helper'); 

var upload = multer({ storage: storage, fileFilter: fileFilter });


const {
  signUp, 
  login,
  accountVerify,
  emailVerify,
  forgotPassword,
  changePassword,
  resetPassword,
  getProfile,
  editProfile,
  contactUs,                                                                                                                                                                                                                                                              
  userSocialLogin,
  logout,
  resendMail,
  emailVerifyPage,
  createStudent,
  createFaculty,
  getAllStudents,
  getAllFaculties,
  viewDetails,
  createCourse,
  courseList,
  assignCourseFaculty,
  selectCourse,
  studentCourseList,
  facultyCourseList,
  addStudentAttendance,
  getStudentAttendance,
  addFacultyAttendance,
  getFacultyAttendance,
  addAnnouncement,
  getAnnouncement,
  createProgram,
  programList,
  programDetails,
  uploadExamTimeTable
} = require('../controllers/user.controller')
//Common

router.post('/login',login_validator, validatorFunc, login)
router.get('/account-verify', accountVerify)
router.post('/forgot-password', forgotPassword_validator, validatorFunc, forgotPassword)
router.put('/change-password', changePassword_validator,validatorFunc, authenticate, changePassword)
router.post('/reset-password', restPassword_validator,validatorFuncRender, resetPassword)
router.get('/',authenticate, getProfile)
router.put('/',authenticate, editProfile)

router.post('/resend-mail', forgotPassword_validator, validatorFunc, resendMail)
router.get('/logout',authenticate, logout)

router.get('/get-all-announcement', authenticate, getAnnouncement)
router.get('/program-details/:program_id',authenticate, programDetails) 

//Admin
router.post('/create-student',login_validator, validatorFunc,adminAuthenticate, createStudent)
router.post('/create-faculty',login_validator, validatorFunc, adminAuthenticate, createFaculty)
router.get('/get-all-students', authenticate, getAllStudents)
router.get('/get-all-faculties', adminAuthenticate, getAllFaculties)
router.get('/user-details/user_id',authenticate, viewDetails)
router.post('/create-course',adminAuthenticate, createCourse)
router.get('/course-list',authenticate, courseList)
router.post('/assign-course-faculty',adminAuthenticate, assignCourseFaculty)
router.post('/add-faculty-attendance',adminAuthenticate, addFacultyAttendance)
router.post('/add-announcement',adminAuthenticate, addAnnouncement)
router.post('/create-program',adminAuthenticate, createProgram)
router.get('/program-list',authenticate, programList)
// router.post('/upload-exam-time-table',adminAuthenticate, createProgram)

router.post('/upload-exam-time-table', authenticate, function (req, res, next) {
  try {

    req.errorMessage = "";
    next();
  } catch (error) {
    console.log("error...............", err)
    res.status(422).send(error.message)
  }
}, upload.fields([
  { name: 'exam', maxCount: 1 },
]), function (req, res, next) {
  if (req.errorMessage != "") {
    console.log("error...............")
    var response = req.response;
    response.setMessage = req.errorMessage
    response.setStatus = 422;
    response.setErrorStack = req.errorMessage
    res.status(422).send(response);
  } else { next(); }

}, uploadExamTimeTable);


//Faculty
router.get('/faculty-course-list',authenticate, facultyCourseList)
router.post('/add-student-attendance',facultyAuthenticate, addStudentAttendance)
router.get('/get-faculty-attendance',authenticate, getFacultyAttendance)


//Students
router.post('/select-course',authenticate, selectCourse)
router.get('/student-course-list',authenticate, studentCourseList)
router.post('/contact-us', add_contactus_validator,validatorFunc,authenticate,contactUs)
router.get('/get-student-attendance',authenticate, getStudentAttendance)




router.post('/')

module.exports = router;
