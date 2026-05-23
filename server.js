require('dotenv').config();
const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ─── MODELS ───────────────────────────────────────────────────────────
const AdminSchema = new mongoose.Schema({ username:{type:String,required:true,unique:true,lowercase:true}, password:{type:String,required:true} });
AdminSchema.pre('save',async function(next){if(!this.isModified('password'))return next();this.password=await bcrypt.hash(this.password,10);next();});
AdminSchema.methods.matchPassword=function(p){return bcrypt.compare(p,this.password);};
const Admin=mongoose.model('Admin',AdminSchema);

const ServiceSchema=new mongoose.Schema({icon:{type:String,default:'🏗️'},ar:{type:String,required:true},en:{type:String,required:true},descAr:{type:String,default:''},descEn:{type:String,default:''},features:{ar:[String],en:[String]},order:{type:Number,default:0},active:{type:Boolean,default:true}},{timestamps:true});
const Service=mongoose.model('Service',ServiceSchema);

const TeamSchema=new mongoose.Schema({nameAr:{type:String,required:true},nameEn:{type:String,required:true},roleAr:{type:String,default:''},roleEn:{type:String,default:''},bioAr:{type:String,default:''},bioEn:{type:String,default:''},photo:{type:String,default:''},emoji:{type:String,default:'👨‍💼'},order:{type:Number,default:0},active:{type:Boolean,default:true}},{timestamps:true});
const Team=mongoose.model('TeamMember',TeamSchema);

const ProjectSchema=new mongoose.Schema({nameAr:{type:String,required:true},nameEn:{type:String,required:true},statusAr:{type:String,default:'مخطط'},statusEn:{type:String,enum:['Completed','In Progress','Planned'],default:'Planned'},year:{type:Number,default:()=>new Date().getFullYear()},descAr:{type:String,default:''},descEn:{type:String,default:''},image:{type:String,default:''},order:{type:Number,default:0},active:{type:Boolean,default:true}},{timestamps:true});
const Project=mongoose.model('Project',ProjectSchema);

const MessageSchema=new mongoose.Schema({name:{type:String,required:true},email:{type:String,required:true},subject:{type:String,default:''},message:{type:String,required:true},read:{type:Boolean,default:false}},{timestamps:true});
const Message=mongoose.model('Message',MessageSchema);

const SiteInfoSchema=new mongoose.Schema({nameAr:{type:String,default:'البناء الراسخ'},nameEn:{type:String,default:'Solid Build Co.'},address:{type:String,default:''},phone:{type:String,default:''},email:{type:String,default:''},logo:{type:String,default:''},singleton:{type:Boolean,default:true,unique:true}},{timestamps:true});
const SiteInfo=mongoose.model('SiteInfo',SiteInfoSchema);

const TestimonialSchema=new mongoose.Schema({nameAr:{type:String,required:true},nameEn:{type:String,required:true},roleAr:{type:String,default:''},roleEn:{type:String,default:''},textAr:{type:String,default:''},textEn:{type:String,default:''},stars:{type:Number,default:5},active:{type:Boolean,default:true}},{timestamps:true});
const Testimonial=mongoose.model('Testimonial',TestimonialSchema);

const FaqSchema=new mongoose.Schema({questionAr:{type:String,required:true},questionEn:{type:String,required:true},answerAr:{type:String,default:''},answerEn:{type:String,default:''},order:{type:Number,default:0},active:{type:Boolean,default:true}},{timestamps:true});
const Faq=mongoose.model('Faq',FaqSchema);

const BlogSchema=new mongoose.Schema({titleAr:{type:String,required:true},titleEn:{type:String,required:true},excerptAr:{type:String,default:''},excerptEn:{type:String,default:''},tagAr:{type:String,default:'أخبار'},tagEn:{type:String,default:'News'},emoji:{type:String,default:'📰'},date:{type:String,default:()=>new Date().toISOString().split('T')[0]},active:{type:Boolean,default:true}},{timestamps:true});
const Blog=mongoose.model('Blog',BlogSchema);

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────
function protect(req,res,next){const auth=req.headers.authorization;if(!auth||!auth.startsWith('Bearer '))return res.status(401).json({success:false,message:'غير مصرح'});try{req.admin=jwt.verify(auth.split(' ')[1],process.env.JWT_SECRET);next();}catch{res.status(401).json({success:false,message:'الجلسة منتهية'});}}

// ─── AUTH ─────────────────────────────────────────────────────────────
app.post('/api/auth/login',async(req,res)=>{try{const{username,password}=req.body;if(!username||!password)return res.status(400).json({success:false,message:'أدخل البيانات'});const admin=await Admin.findOne({username:username.toLowerCase().trim()});if(!admin||!(await admin.matchPassword(password)))return res.status(401).json({success:false,message:'اسم المستخدم أو كلمة المرور غير صحيحة'});const token=jwt.sign({id:admin._id,username:admin.username},process.env.JWT_SECRET,{expiresIn:'7d'});res.json({success:true,token,admin:{username:admin.username}});}catch(err){res.status(500).json({success:false,message:'خطأ في السيرفر'});}});
app.get('/api/auth/me',protect,(req,res)=>res.json({success:true,admin:req.admin}));

// ─── CRUD HELPER ──────────────────────────────────────────────────────
function crudRoutes(app,path,Model,sortPublic={},sortAll={}){
  app.get('/api/'+path,async(req,res)=>{const d=await Model.find({active:true}).sort(sortPublic);res.json({success:true,data:d});});
  app.get('/api/'+path+'/all',protect,async(req,res)=>{const d=await Model.find().sort(sortAll);res.json({success:true,data:d});});
  app.post('/api/'+path,protect,async(req,res)=>{const d=await Model.create(req.body);res.status(201).json({success:true,data:d});});
  app.put('/api/'+path+'/:id',protect,async(req,res)=>{const d=await Model.findByIdAndUpdate(req.params.id,req.body,{new:true});if(!d)return res.status(404).json({success:false,message:'غير موجود'});res.json({success:true,data:d});});
  app.delete('/api/'+path+'/:id',protect,async(req,res)=>{await Model.findByIdAndDelete(req.params.id);res.json({success:true,message:'تم الحذف'});});
}

crudRoutes(app,'services',Service,{order:1,createdAt:1},{order:1,createdAt:1});
crudRoutes(app,'team',Team,{order:1,createdAt:1},{order:1,createdAt:1});
crudRoutes(app,'projects',Project,{year:-1,order:1},{year:-1,order:1});
crudRoutes(app,'testimonials',Testimonial,{},{});
crudRoutes(app,'faqs',Faq,{order:1},{order:1});
crudRoutes(app,'blogs',Blog,{createdAt:-1},{createdAt:-1});

// ─── MESSAGES ─────────────────────────────────────────────────────────
app.post('/api/messages',async(req,res)=>{const{name,email,subject,message}=req.body;if(!name||!email||!message)return res.status(400).json({success:false,message:'يرجى ملء الحقول المطلوبة'});const item=await Message.create({name,email,subject:subject||'',message});res.status(201).json({success:true,message:'تم الإرسال بنجاح! سنتواصل معك قريباً.',data:item});});
app.get('/api/messages',protect,async(req,res)=>{const d=await Message.find().sort({createdAt:-1});res.json({success:true,data:d});});
app.put('/api/messages/:id/read',protect,async(req,res)=>{const d=await Message.findByIdAndUpdate(req.params.id,{read:true},{new:true});if(!d)return res.status(404).json({success:false,message:'غير موجود'});res.json({success:true,data:d});});
app.delete('/api/messages/:id',protect,async(req,res)=>{await Message.findByIdAndDelete(req.params.id);res.json({success:true,message:'تم الحذف'});});

// ─── SITE INFO ────────────────────────────────────────────────────────
app.get('/api/siteinfo',async(req,res)=>{let d=await SiteInfo.findOne({singleton:true});if(!d)d=await SiteInfo.create({singleton:true});res.json({success:true,data:d});});
app.put('/api/siteinfo',protect,async(req,res)=>{const d=await SiteInfo.findOneAndUpdate({singleton:true},{$set:req.body},{new:true,upsert:true});res.json({success:true,data:d,message:'تم الحفظ'});});

// ─── HEALTH ───────────────────────────────────────────────────────────
app.get('/api/health',(req,res)=>res.json({success:true,message:'🚀 MongoDB Server',db:mongoose.connection.readyState===1?'connected':'disconnected'}));

// ─── FRONTEND ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname,'client')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'client','index.html')));

// ─── SEED ─────────────────────────────────────────────────────────────
async function seed(){
  if(!(await Admin.findOne({username:process.env.ADMIN_USERNAME}))){
    await Admin.create({username:process.env.ADMIN_USERNAME,password:process.env.ADMIN_PASSWORD});
    console.log('👤 Admin created');
  }
  if(!(await SiteInfo.findOne({singleton:true})))await SiteInfo.create({singleton:true});
  if(!await Service.countDocuments())await Service.insertMany([
    {icon:'🏗️',ar:'البناء والتشييد',en:'Construction',descAr:'تنفيذ المباني السكنية والتجارية والصناعية بأعلى مواصفات الجودة',descEn:'Residential, commercial and industrial buildings',features:{ar:['هياكل خرسانية متطورة','مواد بناء معتمدة','ضمان شامل'],en:['Advanced concrete','Certified materials','Full warranty']},order:1},
    {icon:'📐',ar:'التصميم الهندسي',en:'Engineering Design',descAr:'تصميم معماري وإنشائي متكامل',descEn:'Integrated architectural and structural design',features:{ar:['تصميم إبداعي','حسابات دقيقة','نماذج BIM'],en:['Creative design','Accurate calculations','BIM models']},order:2},
    {icon:'🔧',ar:'الصيانة والترميم',en:'Maintenance',descAr:'صيانة دورية وترميم شامل',descEn:'Periodic maintenance and restoration',features:{ar:['صيانة وقائية','ترميم الواجهات'],en:['Preventive maintenance','Facade restoration']},order:3},
    {icon:'📋',ar:'إدارة المشاريع',en:'Project Management',descAr:'إدارة احترافية متكاملة',descEn:'Professional integrated management',features:{ar:['تخطيط شامل','متابعة يومية'],en:['Full planning','Daily follow-up']},order:4},
    {icon:'⚡',ar:'الأعمال الكهربائية',en:'Electrical Works',descAr:'تركيب جميع الأنظمة الكهربائية',descEn:'All electrical systems',features:{ar:['لوحات التوزيع','إضاءة ذكية'],en:['Distribution panels','Smart lighting']},order:5},
    {icon:'💧',ar:'الأعمال الميكانيكية',en:'Mechanical Works',descAr:'أعمال السباكة والتكييف',descEn:'Plumbing and AC works',features:{ar:['تكييف مركزي','صرف صحي'],en:['Central AC','Drainage']},order:6},
  ]);
  if(!await Team.countDocuments())await Team.insertMany([
    {emoji:'👨‍💼',nameAr:'م. أحمد العمري',nameEn:'Eng. Ahmed Al-Omari',roleAr:'المدير التنفيذي',roleEn:'CEO',bioAr:'مهندس مدني بخبرة 22 عاماً',bioEn:'Civil engineer with 22 years experience',order:1},
    {emoji:'👩‍🏗️',nameAr:'م. سارة الحربي',nameEn:'Eng. Sara Al-Harbi',roleAr:'المدير الهندسي',roleEn:'Engineering Director',bioAr:'متخصصة في التصميم الإنشائي',bioEn:'Structural design specialist',order:2},
    {emoji:'👨‍🔬',nameAr:'م. خالد الدوسري',nameEn:'Eng. Khalid Al-Dosari',roleAr:'مدير المشاريع',roleEn:'Projects Director',bioAr:'خبير في إدارة المشاريع',bioEn:'Project management expert',order:3},
    {emoji:'👩‍💻',nameAr:'م. نورة السعدي',nameEn:'Eng. Noura Al-Saadi',roleAr:'المهندسة المعمارية',roleEn:'Architect',bioAr:'مصممة معمارية متميزة',bioEn:'Distinguished architect',order:4},
  ]);
  if(!await Project.countDocuments())await Project.insertMany([
    {nameAr:'برج الأعمال المركزي',nameEn:'Central Business Tower',statusAr:'منجز',statusEn:'Completed',year:2023},
    {nameAr:'مجمع الوحدات السكنية',nameEn:'Residential Complex',statusAr:'جارٍ',statusEn:'In Progress',year:2024},
    {nameAr:'مستشفى الأمل الجديد',nameEn:'New Hope Hospital',statusAr:'منجز',statusEn:'Completed',year:2022},
  ]);
  if(!await Testimonial.countDocuments())await Testimonial.insertMany([
    {nameAr:'محمد السالم',nameEn:'Mohammed Al-Salem',roleAr:'مالك مجمع تجاري',roleEn:'Commercial Owner',textAr:'شركة البناء الراسخ تجاوزت كل توقعاتي، التزام بالمواعيد وجودة عالية.',textEn:'Solid Build exceeded all my expectations.',stars:5},
    {nameAr:'نوف العتيبي',nameEn:'Nouf Al-Otaibi',roleAr:'مديرة مشروع سكني',roleEn:'Residential PM',textAr:'فريق محترف أنجز المشروع قبل الموعد بأسبوعين.',textEn:'Professional team, completed 2 weeks early.',stars:5},
  ]);
  if(!await Faq.countDocuments())await Faq.insertMany([
    {questionAr:'ما المناطق التي تخدمونها؟',questionEn:'What areas do you serve?',answerAr:'نخدم جميع مناطق المملكة العربية السعودية.',answerEn:'We serve all regions of Saudi Arabia.',order:1},
    {questionAr:'كم يستغرق تنفيذ المشاريع السكنية؟',questionEn:'How long do projects take?',answerAr:'من 8 إلى 18 شهراً حسب الحجم.',answerEn:'8 to 18 months depending on size.',order:2},
    {questionAr:'هل تقدمون ضماناً؟',questionEn:'Do you offer a warranty?',answerAr:'نعم، ضمان 5 سنوات على الهيكل الإنشائي.',answerEn:'Yes, 5-year structural warranty.',order:3},
  ]);
  if(!await Blog.countDocuments())await Blog.insertMany([
    {emoji:'🏗️',titleAr:'إنجاز برج الأعمال المركزي',titleEn:'Central Business Tower Completed',excerptAr:'أعلنا عن إتمام المشروع بنجاح في الموعد المحدد.',excerptEn:'We announced successful on-time completion.',tagAr:'إنجازات',tagEn:'Achievements'},
    {emoji:'🏆',titleAr:'جائزة أفضل شركة مقاولات 2024',titleEn:'Best Construction Company 2024',excerptAr:'حصدنا جائزة أفضل شركة مقاولات للعام 2024.',excerptEn:'We won Best Construction Company 2024.',tagAr:'جوائز',tagEn:'Awards'},
  ]);
  console.log('✅ Seed complete');
}

// ─── START ────────────────────────────────────────────────────────────
const PORT=process.env.PORT||5000;
mongoose.connect(process.env.MONGO_URI)
  .then(async()=>{
    console.log('✅ Connected to MongoDB Atlas');
    await seed();
    app.listen(PORT,()=>{
      console.log('');
      console.log('🚀 Server: http://localhost:'+PORT);
      console.log('🔐 Admin: '+process.env.ADMIN_USERNAME);
      console.log('');
    });
  })
  .catch(err=>{
    console.error('❌ MongoDB failed:',err.message);
    process.exit(1);
  });
