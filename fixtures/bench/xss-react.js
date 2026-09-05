import React from 'react';

function Comment({ body }) {
  return (
    <div
      className="comment"
      dangerouslySetInnerHTML={{ __html: renderMarkdown(body) }} // L7 命中
    />
  );
}

function Safe({ text }) {
  return <div>{text}</div>; // L13 React 自动转义
}
