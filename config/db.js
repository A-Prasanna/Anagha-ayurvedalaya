const mongoose = require('mongoose');
const config = require('config');
const db = config.get('mongoURI');

const connectDB = async () =>{
    try
    {
        await mongoose.connect(db,{
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true,
            useFindAndModify:false
        });
        console.log('MongoDB Connected...');
    }
    catch(err)
    {
        console.error(err);
        //exit process with failure
        process.exit(0);
    }
}

module.exports = connectDB;
