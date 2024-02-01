// 文章的处理函数模块
const path = require('path')
const db = require('../db/index')

// 发布文章的处理函数
exports.addArticle = (req, res) => {
  console.log(req.file)
  if (!req.file || req.file.fieldname !== 'cover_img') return res.cc('文章封面是必选参数！')

  // TODO：证明数据都是合法的，可以进行后续业务逻辑的处理
  // 处理文章的信息对象
  const articleInfo = {
    // 标题、内容、发布状态、所属分类的Id
    ...req.body,
    // 文章封面的存放路径
    cover_img: path.join('/uploads', req.file.filename),
    // 文章的发布时间
    pub_date: new Date(),
    // 文章作者的Id
    author_id: req.user.id,
  }

  const sql = `insert into ev_articles set ?`
  db.query(sql, articleInfo, (err, results) => {
    if (err) return res.cc(err)
    if (results.affectedRows !== 1) return res.cc('发布新文章失败！')
    res.cc('发布文章成功！', 0)
  })
}

// 获取文章列表
exports.listArticle = (req, res) => {
  const index = (req.query.pagenum - 1) * req.query.pagesize
  const info = {
    ...req.query,
    index,
    author_id: req.user.id
  }

  const q = `SELECT COUNT(*) AS total FROM ev_articles a WHERE a.is_delete=0 and a.state=? and a.cate_id=? and a.author_id=?`
  db.query(q, [info.state, info.cate_id, info.author_id], (e, r) => {
    if (e) return res.cc(e)
    
    const sql = `select * from ev_articles a join ev_article_cate b on a.cate_id=b.id where a.is_delete=0 and a.state=? and a.cate_id=? and a.author_id=? order by a.id asc limit ?,?`
    db.query(sql, [info.state, info.cate_id, info.author_id, info.index, info.pagesize], (err, results) => {
      res.send({
        status: 0,
        message: '获取文章数据成功！',
        data: results,
        total: r[0].total
      })
    })
  })
}
