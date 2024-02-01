# 文档

### 前端
1. jQuery、artTemplate、layUI编写资讯发布后台
2. cropper实现图片裁剪
3. tinymce实现富文本
4. 实现用户后台注册、登录、用户信息管理、文章分类、文章分布等模块

### 后端
1. express、mysql、jwt编写资讯发布后台接口
2. 项目初始化，安装nodemon,实现热更新。安装express,创建服务器。配置cors跨域、表单请求数据解析中间件
3. 创建路由模块，路由处理函数模块
4. 创建数据库模块，启动mySql, 创建数据库表，下载mySql模块，连接数据库
5. 创建用户注册模块，定义用户注册接口路由、参数校验中间件、密码加密处理、数据库入库操作，以及错误捕获返回
6. 创建用户登录模块，定义用户登录接口路由、参数校验中间件、密码解密对比，以及token的生成与解析，完成后续接口的用户身份认证
7. 创建用户信息模块，实现用户信息的查询、修改以及base64的图像数据上传
8. 


### 案例

###### 初始化项目
> app.js 入口文件
1. 创建服务器
安装express: npm i express
```js
// 导入 express
const express = require('express')
// 创建服务器的实例对象
const app = express()

// 启动服务器
app.listen(3007, () => {
  console.log('api server running at http://127.0.0.1:3007')
})
```

2. 配置cors跨域
安装cors中间件：npm i cors
```js
// 导入并配置 cors 中间件
const cors = require('cors')
app.use(cors())
```

3. 配置表单解析中间件
```js
// 配置解析表单数据的中间件，注意：这个中间件，只能解析 application/x-www-form-urlencoded 格式的表单数据
app.use(express.urlencoded({ extended: false }))
```

router 存放路由模块
router_handler 存放路由处理函数

4. 初始化路由
```js
// router/user.js

const express = require('express')
const router = express.Router()

// 导入用户路由处理函数对应的模块
const user_handler = require('../router_handler/user')

// 注册新用户
router.post('/reguser', user_handler.regUser)
// 登录
router.post('/login', user_handler.login)

module.exports = router
```

5. 导入注册路由
```js
// 导入并使用用户路由模块
const userRouter = require('./router/user')
app.use('/api', userRouter)
```

6. 定义路由处理函数
```js
// router_handler/user.js

// 注册新用户的处理函数
exports.regUser = (req, res) => {
  // 获取客户端提交到服务器的用户信息
  const userinfo = req.body

  // 定义 SQL 语句，查询用户名是否被占用
  // 操作数据库
  // ......
}

// 登录的处理函数
exports.login = (req, res) => {
  // 接收表单的数据
  const userinfo = req.body
  // 定义 SQL 语句
  // 操作数据库
  // ......
}
```

7. 连接数据库
创建用户表，表字段包括，id(键)、username、password、email、user_pic
安装mySql模块：npm i mysql
```js
// db/index.js
// 连接数据库
const mysql = require('mysql')

const db = mysql.createPool({
  host: '127.0.0.1',
  user: 'root',
  password: '123456',
  database: 'zx',
})

module.exports = db
```

8. 导入与操作数据库
```js
// router_handler/user.js

// 导入数据库操作模块
const db = require('../db/index')

// 定义 SQL 语句
const sql = `select * from ev_users where username=?`
// 执行 SQL 语句，根据用户名查询用户的信息
db.query(sql, userinfo.username, (err, results) => {
// 执行 SQL 语句失败
if (err) return res.cc(err)
// 执行 SQL 语句成功，但是获取到的数据条数不等于 1
if (results.length !== 1) return res.cc('登录失败！')

res.send({
    status: 0,
    message: '登录成功！'
})
```

###### 用户注册接口
http://127.0.0.1:3007/api/reguser
post
body(x-www-form-urlencodeed) 默认
username、password

1. 路由处理函数
```js
// 导入数据库操作模块
const db = require('../db/index')
// 导入 bcryptjs 这个包, 密码加密
const bcrypt = require('bcryptjs')
// 导入生成 Token 的包
const jwt = require('jsonwebtoken')
// 导入全局的配置文件
const config = require('../config')

// 注册新用户的处理函数
exports.regUser = (req, res) => {
  // 获取客户端提交到服务器的用户信息
  const userinfo = req.body
  // 对表单中的数据，进行合法性的校验
  if (!userinfo.username || !userinfo.password) {
    return res.send({ status: 1, message: '用户名或密码不合法！' })
  }

  // 定义 SQL 语句，查询用户名是否被占用
  const sqlStr = 'select * from ev_users where username=?'
  db.query(sqlStr, userinfo.username, (err, results) => {
    // 执行 SQL 语句失败
    if (err) {
      return res.send({ status: 1, message: err.message })
    }
    // 判断用户名是否被占用
    if (results.length > 0) {
      return res.send({ status: 1, message: '用户名被占用，请更换其他用户名！' })
    }
    // 调用 bcrypt.hashSync() 对密码进行加密
    userinfo.password = bcrypt.hashSync(userinfo.password, 10)
    // 定义插入新用户的 SQL 语句
    const sql = 'insert into ev_users set ?'
    // 调用 db.query() 执行 SQL 语句
    db.query(sql, { username: userinfo.username, password: userinfo.password }, (err, results) => {
      // 判断 SQL 语句是否执行成功
      if (err) return res.send({ status: 1, message: err.message })
      // 判断影响行数是否为 1
      if (results.affectedRows !== 1) return res.send({ status: 1, message: '注册用户失败，请稍后再试！' })
      // 注册用户成功
      res.send({ status: 0, message: '注册成功！' })
    })
  })
}
```

2. 密码加密
安装插件bcryptjs
```js
// 导入bcryptjs
const bcrypt = require('bcryptjs')
// 调用 bcrypt.hashSync(明文密码，随机长度) 对密码进行加密
userinfo.password = bcrypt.hashSync(userinfo.password, 10)
```

3. 简化res.send()报错中间件
在路由之前，声明全局中间件，为res挂载res.cc()函数
```js
// 一定要在路由之前，封装 res.cc 函数
app.use((req, res, next) => {
  // status 默认值为 1，表示失败的情况
  // err 的值，可能是一个错误对象，也可能是一个错误的描述字符串
  res.cc = function (err, status = 1) {
    res.send({
      status,
      message: err instanceof Error ? err.message : err,
    })
  }
  next()
})
```

4. 表单数据校验
安装第三方验证规则包：npm install joi
安装第三方验证模块：npm install @escook/express-joi
```js
// 新建 schema/user.js 用户信息验证模块，并初始化代码如下
// 导入定义验证规则的包
const joi = require('joi')

// 定义用户名和密码的验证规则
const username = joi.string().alphanum().min(1).max(10).required()
const password = joi
  .string()
  .pattern(/^[\S]{6,12}$/)
  .required()

// 定义验证注册和登录表单数据的规则对象
exports.reg_login_schema = {
  body: {
    username,
    password,
  },
}


// ---------------------------------
// router/user.js
// 导入用户路由处理函数对应的模块
const user_handler = require('../router_handler/user')

// 导入验证数据的中间件
const expressJoi = require('@escook/express-joi')
// 导入需要的验证规则对象
const { reg_login_schema } = require('../schema/user')

// 注册新用户
router.post('/reguser', expressJoi(reg_login_schema), user_handler.regUser)
```

5. 错误捕获中间件
```js
const joi = require('joi')
// 定义错误级别的中间件
app.use((err, req, res, next) => {
  // 验证失败导致的错误
  if (err instanceof joi.ValidationError) return res.cc(err)
  // 身份认证失败后的错误
  if (err.name === 'UnauthorizedError') return res.cc('身份认证失败！')
  // 未知的错误
  res.cc(err)
})
```

###### 用户登录接口
http://127.0.0.1:3007/api/login
post
username、password

1. 调用bcrypt.compareSync(用户提交密码，数据库中的密码)比较密码是否一致
```js
// 导入 bcryptjs 这个包
const bcrypt = require('bcryptjs')
// 判断密码是否正确
const compareResult = bcrypt.compareSync(userinfo.password, results[0].password)
if (!compareResult) return res.cc('登录失败！')
```

2. 生成token
```js
// 安装生成Token字符串的插件
// npm i jsonwebtoken
// 导入生成 Token 的包
const jwt = require('jsonwebtoken')
// 创建config.js,向外共享 加密 和 还原 token 的jwtSecretKey 字符串
// 导入全局的配置文件
const config = require('../config')

// 查询用户信息......

// 在服务器端生成 Token 的字符串
const user = { ...results[0], password: '', user_pic: '' }
// 对用户的信息进行加密，生成 Token 字符串
const tokenStr = jwt.sign(user, config.jwtSecretKey, { expiresIn: config.expiresIn })
// 调用 res.send() 将 Token 响应给客户端
res.send({
    status: 0,
    message: '登录成功！',
    token:  'Bearer ' + tokenStr,
})
```

3. 解析token中间件
```js
// 安装解析token中间件
// npm i express-jwt

// 一定要在路由之前配置解析 Token 的中间件
const expressJWT = require('express-jwt')
const config = require('./config')

// 使用unless排除不需要进行token身份认证的接口
// req对象上的user属性，是Token 解析成功后，express-jwt 中间件帮我们挂载上去的
app.use(expressJWT({ secret: config.jwtSecretKey }).unless({ path: [/^\/api/] }))
```

###### 获取用户信息接口
http://127.0.0.1:3007/my/userinfo
get
token、token中的用户id(req.user.id)

1. ajax封装headers身份认证
```js
// 注意：每次调用 $.get() 或 $.post() 或 $.ajax() 的时候，
// 会先调用 ajaxPrefilter 这个函数
// 在这个函数中，可以拿到我们给Ajax提供的配置对象
$.ajaxPrefilter(function(options) {
  // 在发起真正的 Ajax 请求之前，统一拼接请求的根路径
  options.url = 'http://127.0.0.1:3007' + options.url

  // 统一为有权限的接口，设置 headers 请求头
  if (options.url.indexOf('/my/') !== -1) {
    options.headers = {
      Authorization: localStorage.getItem('token') || ''
    }
  }

  // 全局统一挂载 complete 回调函数
  options.complete = function(res) {
    // console.log('执行了 complete 回调：')
    // console.log(res)
    // 在 complete 回调函数中，可以使用 res.responseJSON 拿到服务器响应回来的数据
    if (res.responseJSON.status === 1 && res.responseJSON.message === '身份认证失败！') {
      // 1. 强制清空 token
      localStorage.removeItem('token')
      // 2. 强制跳转到登录页面
      location.href = '/login.html'
    }
  }
})
```

###### 更新用户信息接口
http://127.0.0.1:3007/my/userinfo
post
body: id、nickname、email


###### 重置密码接口
http://127.0.0.1:3007/my/updatepwd
post
body: oldPwd、newPwd
1. 新密码校验
```js
// schema/user.js
// 验证规则对象 - 更新密码
// 导入定义验证规则的包
const joi = require('joi')
// 1. joi.ref('oldPwd')表示 newPwd 的值必须和 oldPwd 的值保持一致
// 2. joi.not(joi.ref('oldPwd'))表示 newPwd 的值不能和 oldPwd 的值一样
// 3. .concat() 用于合并两条验证规则
exports.update_password_schema = {
  body: {
    oldPwd: password,
    newPwd: joi.not(joi.ref('oldPwd')).concat(password),
  },
}
```

###### 更新用户头像接口
http://127.0.0.1:3007/my/update/avatar
post
body: avatar 
avatar是base64的字符串



创建文章分类表 ev_article_cate, 包括id、name、alias、is_delete
###### 查询文章分类列表
http://127.0.0.1:3007/my/article/cates
get
无参数

###### 新增文章分类
http://127.0.0.1:3007/my/article/addcates
post
body: name、alias

1. 查重校验
```js
// router_handler/aartcate.js
// 新增文章分类的处理函数
exports.addArticleCates = (req, res) => {
  // 1. 定义查重的 SQL 语句
  const sql = `select * from ev_article_cate where name=? or alias=?`
  // 2. 执行查重的 SQL 语句
  db.query(sql, [req.body.name, req.body.alias], (err, results) => {
    // 3. 判断是否执行 SQL 语句失败
    if (err) return res.cc(err)

    // 4.1 判断数据的 length
    if (results.length === 2) return res.cc('分类名称与分类别名被占用，请更换后重试！')
    // 4.2 length 等于 1 的三种情况
    if (results.length === 1 && results[0].name === req.body.name && results[0].alias === req.body.alias) return res.cc('分类名称与分类别名被占用，请更换后重试！')
    if (results.length === 1 && results[0].name === req.body.name) return res.cc('分类名称被占用，请更换后重试！')
    if (results.length === 1 && results[0].alias === req.body.alias) return res.cc('分类别名被占用，请更换后重试！')

    // 定义插入文章分类的 SQL 语句
    const sql = `insert into ev_article_cate set ?`
    // 执行插入文章分类的 SQL 语句
    db.query(sql, req.body, (err, results) => {
      if (err) return res.cc(err)
      if (results.affectedRows !== 1) return res.cc('新增文章分类失败！')
      res.cc('新增文章分类成功！', 0)
    })
  })
}
```

###### 删除文章分类
http://127.0.0.1:3007/my/article/deletecate/:id
get
http://127.0.0.1:3007/my/article/deletecate/1

###### 获取文章分类
http://127.0.0.1:3007/my/article/cates/:id
get
http://127.0.0.1:3007/my/article/cates/1

###### 更新文章分类
http://127.0.0.1:3007/my/article/updatecate
post
body: id、name、alias


创建文章表 ev_articles, 包括id、title、content、cover_img、pub_date、state、is_delete、cate_id、author_id
###### 发布文章
http://127.0.0.1:3007/my/article/add
post
body: title、cate_id、content、state、cover_img
1. 使用multer解析formData格式数据
```js
// npm i multer
// 在router/article.js 模块中导入并配置 multer
// 导入 multer 和 path
const multer = require('multer')
const path = require('path')

// 创建 multer 的实例, dest指定文件存放路径
const uploads = multer({ dest: path.join(__dirname, '../uploads') })

// 添加路由中间件
// uploads.single(）是一个局部生效中间件，用来解析 FormData 格式的表单数据
// 将文件类型的数据，解析并挂载到 req.file 属性中
// 将文件类型的数据，解析并挂载到 req.body 属性中
router.post('/add', uploads.single('cover_img'), expressJoi(add_article_schema), article_handler.addArticle)
```

2. 静态资源托管
```js
// 在app.js中，使用express.static()中间件，将uploads目录中的图片托管为静态资源
app.use('/uploads', express.static('./uploads'))
```

###### 获取文章列表
http://127.0.0.1:3007/my/article/list
get
pagenum、pagesize、cate_id、state




















