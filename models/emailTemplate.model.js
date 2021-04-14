const mongoose = require('mongoose');

var Schema = mongoose.Schema;

let emailSchema = new mongoose.Schema({
    id:{
        type: Number,
    },
    title: {
        type: String,
        default: null,
        trim: true,
    },
    keys:{
        type: String,
        default: null,
        trim: true,
    },
    subject: {
        type: String,
        default: null,
        trim: true,
    },
    body: {
        type: String,
        default: null,
        trim: true,
    },
    slug: {
        type: String,
        default: null,
        trim: true,
    },
    status:{
        type:Number,
        default:1
    },
    createdAt: {
        type: Number,
    },
    updatedAt: {
        type: Number,
    },
    syncAt:{
        type: Number,
    },
    deletedAt: {
        type: Number,
        default:null
    },
});

emailSchema.index({"slug": 1});
emailSchema.index({"title": 1});

let EmailFormat = mongoose.model('emailTemplates', emailSchema);
module.exports = EmailFormat;