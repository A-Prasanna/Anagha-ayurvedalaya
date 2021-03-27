const express = require ('express');

const router = express.Router();

const auth = require('../../middleware/auth');

const Profile = require('../../models/Profile');

const User = require('../../models/User');

const {check, validationResult} = require('express-validator');

//@route  GET api/profile/me
//@desc   Get current user profile
//@acess  private
router.get('/me', auth, async (req, res) => {
    try{
        const profile = await Profile.findOne({user : req.user.id}).populate('user',['name','avatar']);
        if(!profile){
            return res.status(400).json({msg : 'there is no profile for this user'});
        }
        res.json(profile);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

//@route  POST api/profile
//@desc   Create or update user profile
//@acess  private

router.post('/',[
    auth,[
    check('status', 'status is required').not().isEmpty(),
    check('skills','skills is required').not().isEmpty()
    ]],
async (req, res) =>{
        const errors = validationResult(req);
        if(!errors.isEmpty()){
            return res.status(400).json({errors: errors.array()});
        }
        const {
            company,website,location,bio,status,
            githubusername,skills,youtube,facebook,twitter,instagram,linkedin
        } = req.body;

        //build profile obect
        const profileFields = {};
        profileFields.user = req.user.id;
        if(company) profileFields.company = company;
        if(website) profileFields.website = website;
        if(location) profileFields.location = location;
        if(bio) profileFields.bio = bio;
        if(status) profileFields.status = status;
        if(githubusername) profileFields.githubusername = githubusername;
        if(skills) {
            profileFields.skills = skills.split(',').map(skill => skill.trim()); 
        }

        //build social obect
        profileFields.social = {}
        if(youtube) profileFields.social.youtube = youtube;
        if(twitter) profileFields.social.twitter = twitter;
        if(facebook) profileFields.social.facebook = facebook;
        if(linkedin) profileFields.social.linkedin = linkedin;
        if(instagram) profileFields.social.instagram = instagram;
        
        try{
            let profile = await Profile.findOne({user: req.user.id});
            if(profile){ 
                //update
                profile = await Profile.findOneAndUpdate({user: req.user.id}, 
                    { $set: profileFields },
                    {new: true});
                    return res.json(profile);
            }

            //create
            profile = new Profile(profileFields);
            await profile.save();
            res.json(profile);
        }
        catch(err){
            console.error(err.message);
            res.status(500).send('Server error'); 
        }
    }
); 


//@route  GET api/profile
//@desc   get all profile
//@acess  public

router.get('/',async (req, res) => {
    try {
        const profiles = await Profile.find().populate('user',['name','avatar']);
        res.json(profiles); 
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

//@route  GET api/profile/user/:userid
//@desc   get profile by user id
//@acess  public

router.get('/user/:user_id',async (req, res) => {
    try {
        const profile = await Profile.findOne({user: req.params.user_id}).populate('user',['name','avatar']); 
        if(!profile)  return res.status(400).json({msg: 'profile not found'});
        res.json(profile);
    } catch (err) {
        console.error(err.message);
        if(err.kind ==  'ObjectId'){
            return res.status(400).json({msg: 'profile not found'});
        }
        res.status(500).send('Server error');
    }
});

//@route  DELETE api/profile
//@desc   delete profile, user and psots
//@acess  private

router.delete('/',auth, async (req, res) => {
    try {
        //@todo - remove users posts

        //remove profile
        await Profile.findOneAndR
        emove({user: req.user.id });
        
        //remove user
        await User.findOneAndRemove({_id: req.user.id });

        res.json({msg: 'user removed'}); 
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


//@route  PUT api/profile/experience
//@desc   add profile experience
//@acess  private

router.put('/experience', [auth,[
    check('title', 'Title is required').not().isEmpty(),  
    check('company', 'company is required').not().isEmpty(),
    check('from', 'from date is required').not().isEmpty()
    ]
], 
async (req, res) =>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    const{
        title,company,location,from,to,current,description
    } = req.body;

    const newExp = {
        title,
        company,
        location,
        from,
        to,
        current,
        description
    }
    try{
        const profile = await Profile.findOne({user: req.user.id});
        profile.experience.unshift(newExp);
        await profile.save();
        res.json(profile);
    }
    catch(err){
        connsole.error(err.message);
        res.status(500),send('server error');
    } 
});


//@route  DELETE api/profile/experience/:exp_id
//@desc   delete profile experience
//@acess  private

router.delete('/experience/:exp_id', auth, async (req, res) => {
    try{
        const profile = await Profile.findOne({user: req.user.id}); 
        
        // Get remove index
        const removeIndex = profile.experience.map(item => item.id).indexOf(req.param.exp_id);
        profile.experience.splice(removeIndex, 1);
        await profile.save() ;
        res.json(profile);
    }
    catch(err){
        connsole.error(err.message);
        res.status(500),send('server error');
    }
});


//@route  PUT api/profile/education
//@desc   add profile education
//@acess  private

router.put('/education', [auth,[
    check('school', 'school is required').not().isEmpty(),  
    check('degree', 'degree is required').not().isEmpty(),
    check('fieldofstudy', 'field of study is required').not().isEmpty(),
    check('from', 'from date is required').not().isEmpty()
    ]
], 
async (req, res) =>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({errors: errors.array()});
    }

    const{ 
        school,degree,fieldofstudy,from,to,current,description
    } = req.body;

    const newEdu = {
        school,
        degree,
        fieldofstudy,
        from,
        to,
        current,
        description
    }
    try{
        const profile = await Profile.findOne({user: req.user.id});
        profile.education.unshift(newEdu);
        await profile.save();
        res.json(profile);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send('server error');
    } 
});

//@route  DELETE api/profile/education/:edu_id
//@desc   delete profile education
//@acess  private

router.delete('/education/:edu_id', auth, async (req, res) => {
    try{
        const profile = await Profile.findOne({user: req.user.id}); 
        
        // Get remove index
        const removeIndex = profile.education.map(item => item.id).indexOf(req.param.edu_id);
        profile.education.splice(removeIndex, 1);
        await profile.save() ;
        res.json(profile);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send('server error');
    }
});


module.exports= router; 