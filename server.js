const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("./DB/deepseek_json_20250624_124bdd.json");
const middlewares = jsonServer.defaults({
  static: "./public/uploads", // اضافه کردن مسیر استاتیک برای آپلودها
  bodyParser: true, // اجازه می‌دهد json-server خودش bodyParser را مدیریت کند
});
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { log } = require("console");
const slugify = require("slugify");

// تنظیمات
const SECRET_KEY = "your-very-secure-key-123!@#";
const TOKEN_EXPIRY = "1h";

// لیست مسیرهای عمومی که نیاز به احراز هویت ندارند
const PUBLIC_ROUTES = [
  "/register",
  "/login",
  "/courses",
  "/courses/:courseId",
  "/refresh-token",
  "/forgot-password",
];

// لیست مسیرهای ادمین
const ADMIN_ROUTES = [
  "/users",
  "/ban",
  "/offs/all",
  "/offs/:courseId",
  "/teachers/:teacherId", // <-- این خط رو اضافه کن
];

// تنظیمات multer برای آپلود فایل
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = "public/uploads/";
    if (file.fieldname === "avatar") folder += "avatars/";
    else if (file.fieldname === "courseImage") folder += "courses/";
    else if (file.fieldname === "video") folder += "videos/";

    // ایجاد پوشه اگر وجود نداشته باشد
    if (!fs.existsSync(folder)) {
      fs.mkdirSync(folder, { recursive: true });
    }
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // حداکثر 50 مگابایت
  fileFilter: (req, file, cb) => {
    const validTypes = ["image/jpeg", "image/png", "video/mp4"];
    if (validTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error("فرمت فایل نامعتبر است!"), false);
    }
  },
});

// استفاده از میدلورهای json-server
server.use(middlewares);

// اضافه کردن middleware برای افزایش limit حجم درخواست‌ها
server.use(express.json({ limit: "50mb" }));
server.use(express.urlencoded({ extended: true, limit: "50mb" }));

// --- Middleware احراز هویت ---
server.use((req, res, next) => {
  // استخراج مسیر بدون پارامترهای کوئری
  const pathWithoutQuery = req.path.split("?")[0];

  // اگر مسیر عمومی است، اجازه دسترسی بده
  if (
    PUBLIC_ROUTES.some((route) => {
      if (route.includes(":")) {
        const basePath = route.split("/:")[0];
        return pathWithoutQuery.startsWith(basePath);
      }
      return pathWithoutQuery === route;
    })
  ) {
    return next();
  }

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "دسترسی غیرمجاز" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "توکن نامعتبر" });

    // بررسی مسیرهای ادمین
    if (
      ADMIN_ROUTES.some((route) => {
        if (route.includes(":")) {
          const basePath = route.split("/:")[0];
          return pathWithoutQuery.startsWith(basePath);
        }
        return pathWithoutQuery === route;
      })
    ) {
      const db = router.db;
      const userData = db.get("users").find({ id: user.userId }).value();

      if (!userData || userData.role !== "admin") {
        return res.status(403).json({ error: "دسترسی مخصوص ادمین" });
      }
    }

    req.user = user;
    next();
  });
});

// --- روت‌های API ---

server.get("/courses", (req, res) => {
  const db = router.db;

  // گرفتن page و limit از query string
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  // محاسبه offset
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  // گرفتن کل courses از دیتابیس
  const allCourses = db.get("courses").sortBy("createdAt").value();

  // محاسبه تعداد کل صفحات
  const totalPages = Math.ceil(allCourses.length / limit);

  // برگردوندن فقط داده‌های همین صفحه
  const paginatedCourses = allCourses.slice(startIndex, endIndex);

  res.json({
    success: true,
    currentPage: page,
    totalPages,
    courses: paginatedCourses,
  });
});

server.post("/courses", (req, res) => {
  const db = router.db;
  const {
    title,
    overview,
    icon,
    image,
    studentsCount,
    duration,
    isSupport,
    description,
    price,
  } = req.body;

  if (!title || !overview || !icon || !image || !price) {
    return res.status(400).json({ error: "لطفا فیلدهای ضروری را پر کنید" });
  }

  const newCourse = {
    id: uuidv4(),
    title,
    slug: slugify(title, { lower: true, strict: true }), // slug از روی title
    overview,
    icon,
    image,
    studentsCount: studentsCount || 0,
    duration: duration || 0,
    isSupport: isSupport == "true" ? true : false,
    description: description || [],
    price,
    details: title + " Course", // یک مقدار پیش‌فرض برای details
    teacherId: null, // طبق چیزی که گفتی
    sessions: [], // خالی
    createdAt: new Date().toISOString(),
    discount: null,
    originalPrice: null,
  };

  db.get("courses").push(newCourse).write();

  res.status(201).json({
    success: true,
    message: "دوره با موفقیت ایجاد شد",
    course: newCourse,
  });
});

// DELETE /courses/:id
server.delete("/courses/:courseId", (req, res) => {
  const db = router.db;
  const { courseId } = req.params;

  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "توکن ارسال نشده" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "توکن معتبر نیست" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({ error: "توکن نامعتبر" });
    }

    // چک نقش ادمین
    const adminUser = db.get("users").find({ id: user.userId }).value();
    if (!adminUser || adminUser.role !== "admin") {
      return res
        .status(403)
        .json({ error: "دسترسی فقط برای ادمین امکان‌پذیر است" });
    }

    // پیدا کردن دوره
    const course = db.get("courses").find({ id: courseId }).value();
    if (!course) {
      return res.status(404).json({ error: "دوره یافت نشد" });
    }

    // 1️⃣ حذف دوره از جدول courses
    db.get("courses").remove({ id: courseId }).write();

    // 2️⃣ آپدیت users
    db.get("users")
      .value()
      .forEach((u) => {
        if (u.courses?.includes(courseId)) {
          db.get("users")
            .find({ id: u.id })
            .assign({ courses: u.courses.filter((id) => id !== courseId) })
            .write();
        }
      });

    // 3️⃣ آپدیت teachers
    db.get("teachers")
      .value()
      .forEach((t) => {
        if (t.courses?.includes(courseId)) {
          db.get("teachers")
            .find({ id: t.id })
            .assign({ courses: t.courses.filter((id) => id !== courseId) })
            .write();
        }
      });

    // 4️⃣ حذف sessions که شامل courseId هستند
    db.get("sessions")
      .remove((s) => Array.isArray(s.data) && s.data.includes(courseId))
      .write();

    res.status(200).json({
      message: "دوره و تمام وابستگی‌ها حذف شدند",
      deletedCourseId: courseId,
    });
  });
});



server.get("/all-courses", (req, res) => {
  const db = router.db;

  const allCourses = db.get("courses").value();

  res.json(allCourses);
});

server.get("/teachers-with-courses", (req, res) => {
  const db = router.db;
  const page = parseInt(req.query.page) || 1; // تغییر از _page به page برای هماهنگی
  const limit = parseInt(req.query.limit) || 10;

  // همه معلما
  const teachers = db.get("teachers").value();

  // pagination دستی
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const paginatedTeachers = teachers.slice(startIndex, endIndex);

  // embed کردن courses برای هر معلم
  const result = paginatedTeachers.map((teacher) => {
    const teacherCourses = db
      .get("courses")
      .filter((course) => teacher.courseIds?.includes(course.id))
      .value();

    return {
      ...teacher,
      courses: teacherCourses,
    };
  });

  // محاسبه تعداد کل صفحات
  const totalPages = Math.ceil(teachers.length / limit);

  // خروجی هم‌فرمت با مسیر /courses
  res.json({
    success: true,
    currentPage: page,
    totalPages,
    teachers: result,
  });
});

server.get("/users", (req, res) => {
  const db = router.db;

  // گرفتن توکن از هدر Authorization
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .json({ success: false, message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // decode و verify JWT با secret خودت
    const decoded = jwt.verify(token, SECRET_KEY); // <-- اینو با secret خودت عوض کن

    // بررسی نقش ادمین
    if (decoded.role !== "admin") {
      return res.status(403).json({ success: false, message: "Unauthorized" });
    }
  } catch (err) {
    return res.status(403).json({ success: false, message: "Invalid token" });
  }

  // Pagination
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;
  const allUsers = db.get("users").sortBy("createdAt").reverse().value();
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const paginatedUsers = allUsers.slice(startIndex, endIndex);
  const totalPages = Math.ceil(allUsers.length / limit);

  res.json({
    success: true,
    currentPage: page,
    totalPages,
    users: paginatedUsers,
  });
});

server.get("/sessions-with-course", (req, res) => {
  const db = router.db;

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  const allSessions = db.get("sessions").value();

  // Pagination محاسبه
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const paginatedSessions = allSessions.slice(startIndex, endIndex);

  const data = paginatedSessions.map((session) => {
    // پیدا کردن course مربوطه
    const course = db.get("courses").find({ id: session.courseId }).value();

    return {
      ...session,
      course,
    };
  });

  res.json({
    success: true,
    currentPage: page,
    totalPages: Math.ceil(allSessions.length / limit),
    sessions: data,
  });
});

server.get("/seasions-with-course", (req, res) => {
  const db = router.db;

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  const allSessions = db.get("sessions").value();

  // Pagination محاسبه
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;
  const paginatedSessions = allSessions.slice(startIndex, endIndex);

  const data = paginatedSessions.map((session) => {
    // پیدا کردن course مربوطه
    const course = db.get("courses").find({ id: session.courseId }).value();

    return {
      ...session,
      course,
    };
  });

  res.json({
    success: true,
    currentPage: page,
    totalPages: Math.ceil(allSessions.length / limit),
    seasions: data,
  });
});

/**
 * @api {post} /register ثبت‌نام کاربران و معلمین
 * @apiBody {String} username نام کاربری
 * @apiBody {String} password رمز عبور
 * @apiBody {String} email ایمیل
 * @apiBody {String} fullname نام کامل
 * @apiBody {String} role نقش (user یا teacher)
 */
server.post("/register", async (req, res) => {
  const { username, password, email, fullname, phonenumber, role } = req.body;

  // اعتبارسنجی ورودی‌ها
  if (!username || !password || !email || !fullname || !phonenumber) {
    return res.status(400).json({ error: "تمام فیلدها الزامی هستند" });
  }

  if (role !== "user" && role !== "teacher") {
    return res.status(400).json({ error: "نقش نامعتبر (فقط user یا teacher)" });
  }

  const db = router.db;

  // بررسی تکراری نبودن username (هم در کاربران و هم معلمین)
  const userExists = db.get("users").find({ username }).value();
  const teacherExists = db.get("teachers").find({ username }).value();

  if (userExists || teacherExists) {
    return res.status(400).json({ error: "نام کاربری قبلا ثبت شده است" });
  }

  // هش کردن رمز عبور
  const hashedPassword = await bcrypt.hash(password, 10);

  // ایجاد حساب جدید
  const newAccount = {
    id: crypto.randomUUID(),
    username,
    password: hashedPassword,
    email,
    phonenumber,
    fullname,
    role,
    isBanned: false,
  };

  // ذخیره در جدول مناسب بر اساس نقش
  if (role === "teacher") {
    let { stack, courseIds = [] } = req.body;

    // اضافه کردن مدرس به جدول teachers
    db.get("teachers")
      .push({ ...newAccount, courseIds, stack })
      .write();

    // آپدیت کردن course های مربوطه
    courseIds.forEach((courseId) => {
      const course = db.get("courses").find({ id: courseId }).value();
      if (course) {
        db.get("courses")
          .find({ id: courseId })
          .assign({ teacherId: newAccount.id })
          .write();
      }
    });
  } else {
    db.get("users")
      .push({
        ...newAccount,
        purchasedCourses: [],
        cart: [],
      })
      .write();
  }

  res.status(201).json({
    message: "ثبت‌نام موفق",
    userId: newAccount.id,
    role,
  });
});

/**
 * @api {get} /cart دریافت سبد خرید کاربر
 * @apiHeader {String} Authorization توکن کاربر
 */
server.get("/cart", (req, res) => {
  const userId = req.user.userId; // از توکن احراز هویت استخراج می‌شود
  const db = router.db;

  const user = db.get("users").find({ id: userId }).value();
  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  // دریافت اطلاعات کامل دوره‌های موجود در سبد خرید
  const cartItems = db
    .get("courses")
    .filter((course) => user.cart?.includes(course.id))
    .value();

  res.json({
    cart: cartItems,
  });
});

/**
 * @api {post} /cart/add اضافه کردن دوره به سبد خرید
 * @apiHeader {String} Authorization توکن کاربر
 * @apiBody {String} courseId شناسه دوره
 */
server.post("/cart/add", (req, res) => {
  const userId = req.user.userId;
  const { courseId } = req.body;
  const db = router.db;

  if (!courseId) {
    return res.status(400).json({ error: "شناسه دوره الزامی است" });
  }

  const user = db.get("users").find({ id: userId }).value();
  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  const course = db.get("courses").find({ id: courseId }).value();
  if (!course) {
    return res.status(404).json({ error: "دوره یافت نشد" });
  }

  // اگر سبد خرید وجود نداشت، ایجاد می‌کنیم
  if (!user.cart) {
    user.cart = [];
  }

  // بررسی آیا دوره قبلاً در سبد خرید وجود دارد
  if (user.cart.includes(courseId)) {
    return res
      .status(400)
      .json({ error: "این دوره قبلاً در سبد خرید شما وجود دارد" });
  }

  // اضافه کردن دوره به سبد خرید
  db.get("users")
    .find({ id: userId })
    .update("cart", (cart = []) => [...cart, courseId])
    .write();

  res.json({
    success: true,
    message: "دوره به سبد خرید اضافه شد",
    cart: [...user.cart, courseId],
  });
});

/**
 * @api {post} /cart/remove حذف دوره از سبد خرید
 * @apiHeader {String} Authorization توکن کاربر
 * @apiBody {String} courseId شناسه دوره
 */
server.post("/cart/remove", (req, res) => {
  const userId = req.user.userId;
  const { courseId } = req.body;
  const db = router.db;

  if (!courseId) {
    return res.status(400).json({ error: "شناسه دوره الزامی است" });
  }

  const user = db.get("users").find({ id: userId }).value();
  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  if (!user.cart || user.cart.length === 0) {
    return res.status(400).json({ error: "سبد خرید شما خالی است" });
  }

  if (!user.cart.includes(courseId)) {
    return res
      .status(400)
      .json({ error: "این دوره در سبد خرید شما وجود ندارد" });
  }

  // 1. حذف دوره از سبد خرید کاربر
  const updatedCart = user.cart.filter((id) => id !== courseId);
  db.get("users").find({ id: userId }).assign({ cart: updatedCart }).write();

  // 2. دریافت اطلاعات کامل دوره‌های باقیمانده از دیتابیس
  const remainingCourses = updatedCart
    .map((id) => db.get("courses").find({ id }).value())
    .filter(Boolean); // فیلتر کردن موارد null/undefined

  // 3. ارسال پاسخ با جزئیات کامل
  res.json({
    success: true,
    message: "دوره از سبد خرید حذف شد",
    cart: remainingCourses, // ارسال تمام اطلاعات دوره‌ها (شامل icon، قیمت و...)
  });
});

/**
 * @api {post} /login ورود کاربران و معلمین
 * @apiBody {String} username نام کاربری
 * @apiBody {String} password رمز عبور
 */
server.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const db = router.db;
  const users = db.get("users").value();
  const teachers = db.get("teachers").value();

  const account =
    users.find((u) => u.username === username) ||
    teachers.find((t) => t.username === username);

  if (!account) {
    return res.status(401).json({ error: "کاربری با این مشخصات یافت نشد" });
  }

  if (!account.password) {
    return res.status(401).json({ error: "رمز عبور کاربر وجود ندارد" });
  }

  if (account.isBanned) {
    return res.status(403).json({ error: "حساب کاربری شما بن شده است" });
  }

  try {
    const isPasswordValid = await bcrypt.compare(password, account.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "رمز عبور نادرست است" });
    }

    // 1. ساخت access token (انقضا: 15 دقیقه)
    const accessToken = jwt.sign(
      {
        userId: account.id,
        username: account.username,
        role: account.role,
      },
      "access-secret",
      { expiresIn: "15m" }
    );

    // 2. ساخت refresh token (انقضا: 7 روز)
    const refreshToken = jwt.sign(
      {
        userId: account.id,
        tokenType: "refresh", // برای تشخیص نوع توکن
      },
      "refresh-secret", // باید متفاوت از access-secret باشد
      { expiresIn: "7d" }
    );

    // 3. ذخیره refreshToken در دیتابیس (اختیاری - برای باطل کردن توکن در آینده)
    // db.get('users').find({ id: account.id }).assign({ refreshToken }).write();

    // 4. ارسال هر دو توکن در پاسخ
    res.status(200).json({
      message: "ورود موفق",
      userId: account.id,
      role: account.role,
      token: accessToken, // توکن دسترسی کوتاه‌مدت
      refreshToken, // توکن تمدید دسترسی
    });
  } catch (err) {
    console.error("💥 Error during login:", err);
    res.status(500).json({ error: "خطای داخلی سرور" });
  }
});

/**
 * @api {post} /refresh-token ساخت توکن جدید از اطلاعات قبلی
 * @apiBody {String} userId شناسه کاربر
 * @apiBody {String} role نقش کاربر (user یا teacher یا admin)
 */

server.post("/refresh-token", (req, res) => {
  const { userId, role } = req.body;

  if (!userId || !role) {
    return res.status(400).json({ error: "userId و role الزامی هستند" });
  }

  const db = router.db;

  let user;
  let userTable;

  if (role === "teacher") {
    userTable = "teachers";
  } else if (role === "user" || role === "admin") {
    userTable = "users"; // admin هم داخل users است
  } else {
    return res.status(400).json({ error: "نقش نامعتبر است" });
  }

  user = db.get(userTable).find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  const newToken = jwt.sign({ userId, role }, SECRET_KEY, {
    expiresIn: TOKEN_EXPIRY,
  });

  res.json({ token: newToken });
});

/**
 * @api {post} /forgot-password بازیابی رمز عبور
 * @apiBody {String} username نام کاربری
 * @apiBody {String} newPassword رمز عبور جدید
 */

server.post("/forgot-password", async (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
    return res.status(400).json({ error: "نام کاربری و رمز جدید الزامی است" });
  }

  const db = router.db;
  const tables = ["users", "teachers"]; // چون فقط تو این دوتا جدول دنبال کاربر می‌گردی

  let user = null;
  let foundTable = null;

  for (const table of tables) {
    const found = db.get(table).find({ username }).value();
    if (found) {
      user = found;
      foundTable = table;
      break;
    }
  }

  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  db.get(foundTable)
    .find({ username })
    .assign({ password: hashedPassword })
    .write();

  res.json({ success: true, message: "رمز عبور با موفقیت تغییر کرد" });
});

/**
 * @api {post} /ban بن/رفع بن کاربران و معلمین
 * @apiHeader {String} Authorization توکن ادمین
 * @apiBody {String} targetId شناسه کاربر/معلم
 * @apiBody {Boolean} isBanned وضعیت بن
 * @apiBody {String} targetType نوع حساب (user/teacher)
 */
server.post("/ban", (req, res) => {
  const { targetId, isBanned, targetType = "user" } = req.body;
  const db = router.db;

  // اعتبارسنجی ورودی‌ها
  if (typeof isBanned !== "boolean") {
    return res
      .status(400)
      .json({ error: "مقدار isBanned باید true/false باشد" });
  }

  if (targetType !== "user" && targetType !== "teacher") {
    return res
      .status(400)
      .json({ error: "نوع هدف نامعتبر (فقط user یا teacher)" });
  }

  // پیدا کردن جدول هدف
  const targetTable =
    targetType === "user" ? db.get("users") : db.get("teachers");
  const target = targetTable.find({ id: targetId }).value();

  if (!target) {
    return res
      .status(404)
      .json({ error: `${targetType === "user" ? "کاربر" : "معلم"} یافت نشد` });
  }

  // اعمال تغییرات
  targetTable.find({ id: targetId }).assign({ isBanned }).write();

  res.json({
    success: true,
    message: `${targetType === "user" ? "کاربر" : "معلم"} ${
      isBanned ? "بن" : "رفع بن"
    } شد`,
    targetType,
    targetId,
  });
});

/**
 * @api {put} /teachers/:teacherId ویرایش اطلاعات معلم
 * @apiHeader {String} Authorization توکن ادمین یا خود معلم
 * @apiParam {String} teacherId شناسه معلم
 * @apiBody {String} [username] نام کاربری جدید
 * @apiBody {String} [email] ایمیل جدید
 * @apiBody {String} [fullname] نام کامل جدید
 * @apiBody {String} [stack] تخصص جدید
 * @apiBody {String} [phonenumber] شماره تماس جدید
 * @apiBody {String[]} [courseIds] آرایه شناسه‌های دوره‌های جدید
 */
server.put("/teachers/:teacherId", async (req, res) => {
  const { teacherId } = req.params;
  const { username, email, fullname, stack, phonenumber, courseIds } = req.body;
  const db = router.db;

  // 1. پیدا کردن معلم
  const teacher = db.get("teachers").find({ id: teacherId }).value();
  if (!teacher) {
    return res.status(404).json({ error: "معلم یافت نشد" });
  }

  // 2. بررسی مجوز دسترسی (ادمین یا خود معلم)
  const currentUserId = req.user.userId;
  const currentUserRole = req.user.role;

  if (currentUserId !== teacherId && currentUserRole !== "admin") {
    return res
      .status(403)
      .json({ error: "شما مجوز ویرایش این معلم را ندارید" });
  }

  // 3. اعتبارسنجی ورودی‌ها و آماده‌سازی داده‌های به‌روزرسانی
  const updates = {};

  if (username) {
    // بررسی تکراری نبودن username
    const usernameExists =
      db.get("users").find({ username }).value() ||
      db
        .get("teachers")
        .find({ username, id: { $ne: teacherId } })
        .value();

    if (usernameExists) {
      return res
        .status(400)
        .json({ error: "نام کاربری قبلاً استفاده شده است" });
    }
    updates.username = username;
  }

  if (email) updates.email = email;
  if (fullname) updates.fullname = fullname;
  if (stack) updates.stack = stack;
  if (phonenumber) updates.phonenumber = phonenumber;

  // 4. پردازش دوره‌ها در صورت وجود
  if (courseIds && Array.isArray(courseIds)) {
    // 4.1. بررسی وجود تمام دوره‌ها در دیتابیس
    const invalidCourses = courseIds.filter(
      (id) => !db.get("courses").find({ id }).value()
    );

    if (invalidCourses.length > 0) {
      return res.status(404).json({
        error: "برخی دوره‌ها یافت نشدند",
        invalidCourses,
      });
    }

    // 4.2. دریافت دوره‌های قبلی معلم
    const previousCourseIds = teacher.courseIds || [];

    // 4.3. به‌روزرسانی دوره‌های جدید در جدول teachers
    updates.courseIds = courseIds;

    // 4.4. حذف teacherId از دوره‌های قدیمی که دیگر به این معلم تعلق ندارند
    const removedCourses = previousCourseIds.filter(
      (id) => !courseIds.includes(id)
    );

    removedCourses.forEach((courseId) => {
      db.get("courses")
        .find({ id: courseId })
        .assign({ teacherId: null })
        .write();
    });

    // 4.5. اضافه کردن teacherId به دوره‌های جدید
    const addedCourses = courseIds.filter(
      (id) => !previousCourseIds.includes(id)
    );

    addedCourses.forEach((courseId) => {
      db.get("courses")
        .find({ id: courseId })
        .assign({ teacherId: teacherId })
        .write();
    });
  }

  // 5. اعمال به‌روزرسانی‌ها در جدول teachers
  db.get("teachers").find({ id: teacherId }).assign(updates).write();

  // 6. دریافت اطلاعات به‌روزرسانی شده برای پاسخ
  const updatedTeacher = db.get("teachers").find({ id: teacherId }).value();

  res.json({
    success: true,
    message: "اطلاعات معلم با موفقیت به‌روزرسانی شد",
    teacher: {
      id: updatedTeacher.id,
      username: updatedTeacher.username,
      email: updatedTeacher.email,
      fullname: updatedTeacher.fullname,
      stack: updatedTeacher.stack,
      phonenumber: updatedTeacher.phonenumber,
      courseIds: updatedTeacher.courseIds,
    },
  });
});

/**
 * @api {put} /users/:userId ویرایش اطلاعات کاربر
 * @apiHeader {String} Authorization توکن ادمین یا خود کاربر
 * @apiParam {String} userId شناسه کاربر
 * @apiBody {String} [username] نام کاربری جدید
 * @apiBody {String} [email] ایمیل جدید
 * @apiBody {String} [fullname] نام کامل جدید
 * @apiBody {String} [phonenumber] شماره تماس جدید
 */
server.put("/users/:userId", async (req, res) => {
  const { userId } = req.params;
  const { username, email, fullname, phonenumber } = req.body;
  const db = router.db;

  // 1. پیدا کردن کاربر
  const user = db.get("users").find({ id: userId }).value();
  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  // 2. بررسی مجوز دسترسی (ادمین یا خود کاربر)
  const currentUserId = req.user.userId;
  const currentUserRole = req.user.role;

  if (currentUserId !== userId && currentUserRole !== "admin") {
    return res
      .status(403)
      .json({ error: "شما مجوز ویرایش این کاربر را ندارید" });
  }

  // 3. اعتبارسنجی ورودی‌ها و آماده‌سازی داده‌های به‌روزرسانی
  const updates = {};

  if (username) {
    // بررسی تکراری نبودن username
    const usernameExists =
      db
        .get("users")
        .find({ username, id: { $ne: userId } })
        .value() || db.get("teachers").find({ username }).value();

    if (usernameExists) {
      return res
        .status(400)
        .json({ error: "نام کاربری قبلاً استفاده شده است" });
    }
    updates.username = username;
  }

  if (email) updates.email = email;
  if (fullname) updates.fullname = fullname;
  if (phonenumber) updates.phonenumber = phonenumber;

  // 4. اعمال به‌روزرسانی‌ها
  db.get("users").find({ id: userId }).assign(updates).write();

  // 5. دریافت اطلاعات به‌روزرسانی شده برای پاسخ
  const updatedUser = db.get("users").find({ id: userId }).value();

  res.json({
    success: true,
    message: "اطلاعات کاربر با موفقیت به‌روزرسانی شد",
    user: {
      id: updatedUser.id,
      username: updatedUser.username,
      email: updatedUser.email,
      fullname: updatedUser.fullname,
      phonenumber: updatedUser.phonenumber,
      role: updatedUser.role,
    },
  });
});

/**
 * @api {post} /purchase خرید دوره
 * @apiHeader {String} Authorization توکن کاربر
 * @apiBody {String[]} courseIds شناسه‌های دوره
 */
server.post("/purchase", (req, res) => {
  const { courseIds } = req.body;
  const userId = req.user.userId; // دریافت از توکن به جای body

  if (!Array.isArray(courseIds)) {
    return res.status(400).json({ error: "courseIds باید آرایه باشد" });
  }

  const db = router.db;
  const user = db.get("users").find({ id: userId }).value();

  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  // بررسی وجود دوره‌ها در دیتابیس
  const invalidCourses = courseIds.filter(
    (id) => !db.get("courses").find({ id }).value()
  );

  if (invalidCourses.length > 0) {
    return res.status(404).json({
      error: "برخی دوره‌ها یافت نشدند",
      invalidCourses,
    });
  }

  // به‌روزرسانی لیست خریداری‌شده‌ها بدون تکرار
  const updatedPurchased = [
    ...new Set([...user.purchasedCourses, ...courseIds]),
  ];

  // حذف دوره‌های خریداری‌شده از سبد خرید
  const updatedCart = (user.cart || []).filter((id) => !courseIds.includes(id));

  // ثبت تغییرات
  db.get("users")
    .find({ id: userId })
    .assign({
      purchasedCourses: updatedPurchased,
      cart: updatedCart,
    })
    .write();

  res.json({
    success: true,
    purchasedCourses: updatedPurchased,
    cart: updatedCart,
    message: "خرید با موفقیت انجام شد",
  });
});

/**
 * @api {get} /teachers/:teacherId/courses دریافت دوره‌های یک معلم
 * @apiParam {String} teacherId شناسه معلم
 */
server.get("/teachers/:teacherId/courses", (req, res) => {
  const { teacherId } = req.params;
  const db = router.db;

  const teacher = db.get("teachers").find({ id: teacherId }).value();
  if (!teacher) {
    return res.status(404).json({ error: "معلم یافت نشد" });
  }

  // دریافت تمام دوره‌های این معلم از جدول courses
  const teacherCourses = db
    .get("courses")
    .filter((course) => teacher.courseIds.includes(course.id))
    .value();

  res.json({
    teacher: {
      id: teacher.id,
      fullname: teacher.fullname,
    },
    courses: teacherCourses,
  });
});

/**
 * @api {get} /user-courses/:userId دریافت دوره‌های کاربر
 * @apiHeader {String} Authorization توکن کاربر یا ادمین
 */
server.get("/user-courses/:userId", (req, res) => {
  const { userId } = req.params;
  const db = router.db;

  // بررسی دسترسی: یا کاربر مالک داده‌هاست یا ادمین است
  if (req.user.userId !== userId && req.user.role !== "admin") {
    return res.status(403).json({ error: "دسترسی غیرمجاز" });
  }

  const user = db.get("users").find({ id: userId }).value();
  if (!user) {
    return res.status(404).json({ error: "کاربر یافت نشد" });
  }

  const courses = db
    .get("courses")
    .filter((course) => user.purchasedCourses.includes(course.id))
    .value();

  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
    },
    courses,
  });
});

/**
 * @api {get} /courses/discounted دریافت همه دوره‌های دارای تخفیف
 */
server.get("/courses/discounted", (req, res) => {
  const db = router.db;

  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 10;

  // فیلتر دوره‌های دارای تخفیف
  const discountedCourses = db
    .get("courses")
    .filter((course) => course.discount && course.discount > 0)
    .value();

  // محاسبه Pagination
  const startIndex = (page - 1) * limit;
  const endIndex = page * limit;

  const paginatedCourses = discountedCourses.slice(startIndex, endIndex);

  res.json({
    success: true,
    currentPage: page,
    totalPages: Math.ceil(discountedCourses.length / limit),
    offs: paginatedCourses, // کلید offs که خواستی
  });
});

/**
 * @api {post} /offs/all اعمال تخفیف به همه دوره‌ها
 */
server.post("/offs/all", (req, res) => {
  const { percentage } = req.body;

  if (!percentage || percentage < 0 || percentage > 100) {
    return res.status(400).json({ error: "درصد تخفیف نامعتبر است (0-100)" });
  }

  const db = router.db;
  const courses = db.get("courses").value();

  courses.forEach((course) => {
    const originalPrice = course.originalPrice || course.price;
    const discountedPrice = (originalPrice * (100 - percentage)) / 100;

    db.get("courses")
      .find({ id: course.id })
      .assign({
        discount: percentage,
        price: discountedPrice,
        originalPrice,
      })
      .write();
  });

  res.json({
    success: true,
    message: `تخفیف ${percentage}% به همه دوره‌ها اعمال شد`,
  });
});

/**
 * @api {delete} /teachers/:teacherId حذف یک معلم و به‌روزرسانی دوره‌های مربوطه
 * @apiHeader {String} Authorization توکن ادمین
 * @apiParam {String} teacherId شناسه معلم
 * @apiSuccess {String} message پیام موفقیت‌آمیز حذف
 */
server.delete("/courses/:courseId", (req, res) => {
  const db = router.db;
  const { courseId } = req.params;

  // احراز هویت و بررسی دسترسی ادمین
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "توکن ارسال نشده" });
  
  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "توکن معتبر نیست" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(401).json({ error: "توکن نامعتبر" });

    const adminUser = db.get("users").find({ id: user.userId }).value();
    if (!adminUser || adminUser.role !== "admin") {
      return res.status(403).json({ error: "فقط ادمین دسترسی دارد" });
    }

    // دریافت state فعلی
    const currentState = db.getState();

    // 1. حذف از purchasedCourses کاربران
    currentState.users = currentState.users.map(user => ({
      ...user,
      purchasedCourses: user.purchasedCourses 
        ? user.purchasedCourses.filter(id => id !== courseId) 
        : [],
      cart: user.cart 
        ? user.cart.filter(id => id !== courseId) 
        : []
    }));

    // 2. حذف از courseIds معلمان
    currentState.teachers = currentState.teachers.map(teacher => ({
      ...teacher,
      courseIds: teacher.courseIds 
        ? teacher.courseIds.filter(id => id !== courseId) 
        : []
    }));

    // 3. حذف جلسات مربوطه
    currentState.sessions = currentState.sessions.filter(
      session => session.courseId !== courseId
    );

    // 4. حذف خود دوره
    currentState.courses = currentState.courses.filter(
      course => course.id !== courseId
    );

    // ذخیره state جدید
    db.setState(currentState).write();

    res.status(200).json({
      success: true,
      message: "دوره و تمام وابستگی‌های آن با موفقیت حذف شدند"
    });
  });
});

/**
 * @api {delete} /users/:userId حذف کامل یک کاربر از سیستم
 * @apiHeader {String} Authorization توکن ادمین
 * @apiParam {String} userId شناسه کاربر
 * @apiSuccess {String} message پیام موفقیت‌آمیز حذف
 */
server.delete("/users/:userId", (req, res) => {
  const db = router.db;
  const { userId } = req.params;

  // 1. احراز هویت ادمین
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "توکن احراز هویت ارسال نشده" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "فرمت توکن نامعتبر" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "توکن نامعتبر یا منقضی شده" });
    }

    // 2. بررسی نقش ادمین
    const admin = db.get("users").find({ id: decoded.userId }).value();
    if (!admin || admin.role !== "admin") {
      return res
        .status(403)
        .json({ error: "فقط ادمین می‌تواند کاربران را حذف کند" });
    }

    // 3. پیدا کردن کاربر
    const user = db.get("users").find({ id: userId }).value();
    if (!user) {
      return res.status(404).json({ error: "کاربر مورد نظر یافت نشد" });
    }

    // 4. حذف کامل کاربر از جدول users
    db.get("users").remove({ id: userId }).write();

    // 5. پاسخ موفقیت‌آمیز
    res.status(200).json({
      success: true,
      message: "کاربر با موفقیت حذف شد",
      deletedUser: {
        id: user.id,
        username: user.username,
      },
    });
  });
});

/**
 * @api {post} /sessions ایجاد جلسه جدید
 * @apiBody {String} courseId شناسه دوره
 * @apiBody {String} seasion عنوان فصل
 * @apiBody {String} title عنوان جلسه
 * @apiBody {Boolean} isFree رایگان/نقدی
 */
server.post("/sessions", (req, res) => {
  const { courseId, seasion, title, isFree } = req.body;
  const db = router.db;

  // اعتبارسنجی
  if (!courseId || !seasion || !title || !isFree) {
    return res.status(400).json({ error: "پر کردن تمام فیلدها الزامی است" });
  }

  // بررسی وجود دوره
  const course = db.get("courses").find({ id: courseId }).value();
  if (!course) {
    return res.status(404).json({ error: "دوره مورد نظر یافت نشد" });
  }

  // بررسی وجود جلسه مشابه
  const existingSession = db
    .get("sessions")
    .find({ courseId, seasion, title })
    .value();

  if (existingSession) {
    return res.status(409).json({
      error: "این جلسه قبلاً برای این دوره ثبت شده است",
      session: existingSession,
    });
  }

  // ایجاد جلسه جدید
  const newSession = {
    id: `s${Date.now()}`,
    courseId,
    seasion,
    title,
    videos: [],
    isFree: isFree == "true" ? true : false,
  };

  // ذخیره جلسه
  db.get("sessions").push(newSession).write();

  // آپدیت دوره با اضافه کردن sessionId
  db.get("courses")
    .find({ id: courseId })
    .update("sessions", (sessions = []) => [...sessions, newSession.id])
    .write();

  res.status(201).json({
    success: true,
    session: newSession,
    updatedCourse: course.id,
    message: "جلسه با موفقیت ایجاد شد",
  });
});

/**
 * @api {delete} /sessions/:sessionId حذف جلسه
 */
server.delete("/sessions/:sessionId", (req, res) => {
  const { sessionId } = req.params;
  const db = router.db;

  const session = db.get("sessions").find({ id: sessionId }).value();
  if (!session) {
    return res.status(404).json({ error: "جلسه یافت نشد" });
  }

  // حذف از جدول sessions
  db.get("sessions").remove({ id: sessionId }).write();

  // حذف از آرایه sessions در دوره مربوطه
  db.get("courses")
    .find({ id: session.courseId })
    .update("sessions", (sessions) => sessions.filter((id) => id !== sessionId))
    .write();

  res.json({
    success: true,
    deletedSession: sessionId,
    courseId: session.courseId,
    message: "سر فصل با موفقیت حذف شد",
  });
});

server.put("/sessions/:sessionId", (req, res) => {
  const { sessionId } = req.params;
  const { courseId, seasion, title, isFree } = req.body;
  const db = router.db;

  // 1. احراز هویت ادمین
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "توکن احراز هویت ارسال نشده" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "فرمت توکن نامعتبر" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "توکن نامعتبر یا منقضی شده" });
    }

    // 2. بررسی نقش ادمین
    const admin = db.get("users").find({ id: decoded.userId }).value();
    if (!admin || admin.role !== "admin") {
      return res
        .status(403)
        .json({ error: "فقط ادمین می‌تواند سرفصل‌ها را ویرایش کند" });
    }

    // 3. پیدا کردن سرفصل فعلی
    const currentSession = db.get("sessions").find({ id: sessionId }).value();
    if (!currentSession) {
      return res.status(404).json({ error: "سرفصل مورد نظر یافت نشد" });
    }

    // 4. بررسی وجود دوره جدید (اگر courseId تغییر کرده باشد)
    const newCourse = db.get("courses").find({ id: courseId }).value();
    if (!newCourse) {
      return res.status(404).json({ error: "دوره جدید یافت نشد" });
    }

    // 5. اگر دوره تغییر کرده باشد، باید سرفصل از دوره قدیم حذف و به دوره جدید اضافه شود
    if (courseId !== currentSession.courseId) {
      // حذف از دوره قدیم
      db.get("courses")
        .find({ id: currentSession.courseId })
        .update("sessions", (sessions) =>
          sessions.filter((id) => id !== sessionId)
        )
        .write();

      // اضافه به دوره جدید
      db.get("courses")
        .find({ id: courseId })
        .update("sessions", (sessions) => [...sessions, sessionId])
        .write();
    }

    // 6. ویرایش سرفصل در جدول sessions
    db.get("sessions")
      .find({ id: sessionId })
      .assign({
        courseId,
        seasion,
        title,
        isFree,
      })
      .write();

    // 7. پاسخ موفقیت‌آمیز
    res.status(200).json({
      success: true,
      message: "سرفصل با موفقیت ویرایش شد",
      updatedSession: {
        id: sessionId,
        courseId,
        seasion,
        title,
        isFree,
      },
      affectedCourses: {
        oldCourseId: currentSession.courseId,
        newCourseId: courseId,
      },
    });
  });
});

/**
 * @api {post} /sessions/:sessionId/videos اضافه کردن ویدیو به جلسه
 * @apiBody {String} title عنوان ویدیو
 * @apiBody {Number} duration مدت زمان (دقیقه)
 * @apiBody {String} videoUrl آدرس ویدیو
 */
server.post("/sessions/:sessionId/videos", (req, res) => {
  const { sessionId } = req.params;
  const { title, duration, videoUrl } = req.body;
  const db = router.db;

  if (!title || !duration || !videoUrl) {
    return res.status(400).json({ error: "پر کردن تمام فیلدها الزامی است" });
  }

  const session = db.get("sessions").find({ id: sessionId }).value();
  if (!session) {
    return res.status(404).json({ error: "جلسه یافت نشد" });
  }

  const newVideo = {
    id: `v${Date.now()}`,
    title,
    duration,
    videoUrl,
    order: session.videos.length + 1,
  };

  db.get("sessions")
    .find({ id: sessionId })
    .update("videos", (videos = []) => [...videos, newVideo])
    .write();

  res.status(201).json({
    success: true,
    message: "جلسه با موفقیت ایجاد شد",
    addedVideo: newVideo,
  });
});

/**
 * @api {put} /sessions/:sessionId/videos/:videoId ویرایش ویدیو
 * @apiBody {String} [title] عنوان جدید
 * @apiBody {Number} [duration] مدت زمان جدید
 * @apiBody {String} [videoUrl] آدرس جدید
 * @apiBody {Number} [order] ترتیب جدید
 */
server.put("/sessions/:sessionId/videos/:videoId", (req, res) => {
  const { sessionId, videoId } = req.params;
  const { title, duration, videoUrl, order } = req.body;
  const db = router.db;

  const session = db.get("sessions").find({ id: sessionId }).value();
  if (!session) {
    return res.status(404).json({ error: "جلسه یافت نشد" });
  }

  const videoIndex = session.videos.findIndex((v) => v.id === videoId);
  if (videoIndex === -1) {
    return res.status(404).json({ error: "ویدیو یافت نشد" });
  }

  // اعمال تغییرات
  const updatedVideos = [...session.videos];
  if (title) updatedVideos[videoIndex].title = title;
  if (duration) updatedVideos[videoIndex].duration = duration;
  if (videoUrl) updatedVideos[videoIndex].videoUrl = videoUrl;
  if (order) updatedVideos[videoIndex].order = order;

  // ذخیره تغییرات
  db.get("sessions")
    .find({ id: sessionId })
    .assign({ videos: updatedVideos })
    .write();

  res.json({
    success: true,
    updatedVideo: updatedVideos[videoIndex],
  });
});

/**
 * @api {delete} /sessions/:sessionId/videos/:videoId حذف ویدیو
 */
server.delete("/sessions/:sessionId/videos/:videoId", (req, res) => {
  const { sessionId, videoId } = req.params;
  const db = router.db;

  const session = db.get("sessions").find({ id: sessionId }).value();
  if (!session) {
    return res.status(404).json({ error: "جلسه یافت نشد" });
  }

  const videoToDelete = session.videos.find((v) => v.id === videoId);
  if (!videoToDelete) {
    return res.status(404).json({ error: "ویدیو یافت نشد" });
  }

  // حذف ویدیو و به‌روزرسانی ترتیب بقیه
  const updatedVideos = session.videos
    .filter((v) => v.id !== videoId)
    .map((v, index) => ({ ...v, order: index + 1 }));

  db.get("sessions")
    .find({ id: sessionId })
    .assign({ videos: updatedVideos })
    .write();

  res.json({
    success: true,
    deletedVideo: videoId,
    remainingVideos: updatedVideos.length,
  });
});

/**
 * @api {get} /courses/:courseId/sessions دریافت جلسات یک دوره
 */
server.get("/courses/:courseId/sessions", (req, res) => {
  const { courseId } = req.params;
  const db = router.db;

  const course = db.get("courses").find({ id: courseId }).value();
  if (!course) {
    return res.status(404).json({ error: "دوره یافت نشد" });
  }

  const sessions = db.get("sessions").filter({ courseId }).sortBy("id").value();

  res.json({
    courseId,
    sessions,
  });
});

/**
 * @api {post} /offs/:courseId اعمال تخفیف به دوره خاص
 */
server.post("/offs/:courseId", (req, res) => {
  const { percentage } = req.body;
  const { courseId } = req.params;

  if (!percentage || percentage < 0 || percentage > 100) {
    return res.status(400).json({ error: "درصد تخفیف نامعتبر است (0-100)" });
  }

  const db = router.db;
  const course = db.get("courses").find({ id: courseId }).value();

  if (!course) {
    return res.status(404).json({ error: "دوره یافت نشد" });
  }

  if (course.price < 1) {
    return res.status(400).json({ error: "دوره رایگان است" });
  }

  const originalPrice = course.originalPrice || course.price;
  const discountedPrice = (originalPrice * (100 - percentage)) / 100;

  db.get("courses")
    .find({ id: courseId })
    .assign({
      discount: percentage,
      price: discountedPrice,
      originalPrice,
    })
    .write();

  res.json({
    success: true,
    message: `تخفیف ${percentage}% به دوره اعمال شد`,
    newPrice: discountedPrice,
  });
});

/**
 * @api {delete} /offs/:courseId حذف تخفیف از یک دوره
 */
server.delete("/offs/:courseId", (req, res) => {
  const { courseId } = req.params;
  const db = router.db;
  const course = db.get("courses").find({ id: courseId }).value();

  if (!course) {
    return res.status(404).json({ error: "دوره یافت نشد" });
  }

  // حذف تخفیف: حذف فیلد discount و originalPrice، و برگردوندن قیمت اصلی به price
  const originalPrice = course.originalPrice || course.price;

  db.get("courses")
    .find({ id: courseId })
    .assign({
      discount: null,
      price: originalPrice,
      originalPrice: null,
    })
    .write();

  res.json({
    success: true,
    message: `تخفیف دوره حذف شد`,
    newPrice: originalPrice,
  });
});

/**
 * @api {put} /offs/:courseId ویرایش تخفیف دوره
 */
server.put("/offs/:courseId", (req, res) => {
  const { percentage } = req.body;
  const { courseId } = req.params;

  if (!percentage || percentage < 0 || percentage > 100) {
    return res.status(400).json({ error: "درصد تخفیف نامعتبر است (0-100)" });
  }

  console.log(percentage);

  const db = router.db;
  const course = db.get("courses").find({ id: courseId }).value();

  if (!course) {
    return res.status(404).json({ error: "دوره یافت نشد" });
  }

  const originalPrice = course.originalPrice || course.price;
  const discountedPrice = (originalPrice * (100 - percentage)) / 100;

  db.get("courses")
    .find({ id: courseId })
    .assign({
      discount: percentage,
      price: discountedPrice,
      originalPrice,
    })
    .write();

  res.json({
    success: true,
    message: `تخفیف به ${percentage}% بروزرسانی شد`,
    newPrice: discountedPrice,
  });
});

server.put("/courses/:courseId", (req, res) => {
  const db = router.db;
  const { courseId } = req.params;

  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "توکن ارسال نشده" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "توکن معتبر نیست" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({ error: "توکن نامعتبر" });
    }

    // چک نقش ادمین
    const adminUser = db.get("users").find({ id: user.userId }).value();
    if (!adminUser || adminUser.role !== "admin") {
      return res.status(403).json({ error: "دسترسی فقط برای ادمین امکان‌پذیر است" });
    }

    // پیدا کردن دوره
    const course = db.get("courses").find({ id: courseId }).value();
    if (!course) {
      return res.status(404).json({ error: "دوره یافت نشد" });
    }

    // مقادیر قابل ویرایش از بادی
    const {
      title,
      overview,
      price,
      duration,
      studentsCount,
      isSupport,
      description,
    } = req.body;

    const {icon : prevIcon , image : prevImage} = db.get('courses').find({id : courseId}).value();
    console.log(prevIcon , prevImage);

    // بروزرسانی دوره
    const updatedCourse = db
      .get("courses")
      .find({ id: courseId })
      .assign({
        title,
        overview,
        price,
        duration,
        studentsCount,
        isSupport : isSupport == 'true' ? true : false,
        description,
        icon: prevIcon || '',  
        image: prevImage || '', 
      })
      .write();

    res.status(200).json({
      message: "دوره با موفقیت ویرایش شد",
      course: updatedCourse,
    });
  });
});

server.put("/courses/:courseId/icon", (req, res) => {
  const db = router.db;
  const { courseId } = req.params;

  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "توکن ارسال نشده" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "توکن معتبر نیست" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({ error: "توکن نامعتبر" });
    }

    // چک نقش ادمین
    const adminUser = db.get("users").find({ id: user.userId }).value();
    if (!adminUser || adminUser.role !== "admin") {
      return res.status(403).json({ error: "دسترسی فقط برای ادمین امکان‌پذیر است" });
    }

    // پیدا کردن دوره
    const course = db.get("courses").find({ id: courseId }).value();
    if (!course) {
      return res.status(404).json({ error: "دوره یافت نشد" });
    }

    const { icon } = req.body;
    if (!icon) {
      return res.status(400).json({ error: "آیکون الزامی است" });
    }

    const updatedCourse = db
      .get("courses")
      .find({ id: courseId })
      .assign({ icon }) // فقط icon تغییر میکنه
      .write();

    res.status(200).json({
      message: "آیکون دوره با موفقیت ویرایش شد",
      course: updatedCourse,
    });
  });
});

server.put("/courses/:courseId/image", (req, res) => {
  const db = router.db;
  const { courseId } = req.params;

  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ error: "توکن ارسال نشده" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "توکن معتبر نیست" });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({ error: "توکن نامعتبر" });
    }

    // چک نقش ادمین
    const adminUser = db.get("users").find({ id: user.userId }).value();
    if (!adminUser || adminUser.role !== "admin") {
      return res.status(403).json({ error: "دسترسی فقط برای ادمین امکان‌پذیر است" });
    }

    // پیدا کردن دوره
    const course = db.get("courses").find({ id: courseId }).value();
    if (!course) {
      return res.status(404).json({ error: "دوره یافت نشد" });
    }

    const { image } = req.body;
    if (!image) {
      return res.status(400).json({ error: "عکس الزامی است" });
    }

    const updatedCourse = db
      .get("courses")
      .find({ id: courseId })
      .assign({ image }) // فقط image تغییر میکنه
      .write();

    res.status(200).json({
      message: "عکس دوره با موفقیت ویرایش شد",
      course: updatedCourse,
    });
  });
});



// استفاده از روتر json-server
server.use(router);

// راه‌اندازی سرور
server.listen(8080, () => {
  console.log("سرور API در حال اجرا است: http://localhost:8080");
  console.log("مستندات API:");
  console.log(`
  ================================================
  | API Endpoint          | Method | Description |
  ================================================
  | /register            | POST   | ثبت‌نام کاربر |
  | /login               | POST   | ورود کاربر   |
  | /ban                 | POST   | بن کردن کاربر|
  | /purchase            | POST   | خرید دوره‌ها |
  | /user-courses/:userId| GET    | دوره‌های کاربر|
  | /offs/all            | POST   | تخفیف کلی    |
  | /offs/:courseId      | POST   | تخفیف دوره   |
  | /upload-course-image | POST   | آپلود عکس دوره|
  | /upload-session-video| POST   | آپلود ویدئو  |
  ================================================
  `);
});
