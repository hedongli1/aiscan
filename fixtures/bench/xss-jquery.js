// jQuery DOM XSS
export function renderComment(comment) {
  $('#list').html(comment.body); // L4 命中 jQuery html
  $('#list').append(comment.title); // L5 命中 jQuery append
}

export function renderStatic() {
  $('#x').html('<b>ok</b>'); // L9 纯静态不命中
  $('#x').text(comment.body); // L10 text() 安全不命中
}
