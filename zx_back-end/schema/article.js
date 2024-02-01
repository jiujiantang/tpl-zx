const joi = require('joi')

// 分别定义 标题、分类Id、内容、发布状态的校验规则
const title = joi.string().required()
const cate_id = joi.number().integer().min(1).required()
const content = joi.string().required().allow('')
const state = joi.string().valid('已发布', '草稿').required()

// 分别定义 页码值、每页显示数据量、文章分类id、文章发布状态
const pagenum = joi.number().integer().min(1).required()
const pagesize = joi.number().integer().min(1).required()

// 验证规则对象 - 发布文章
exports.add_article_schema = {
  body: {
    title,
    cate_id,
    content,
    state,
  },
}

// 验证规则对象 - 文章列表
exports.list_article_schema = {
  query: {
    pagenum,
    pagesize,
    cate_id,
    state
  }
}
