<template>
  <div class="post">
    <h1>{{ title }}</h1>
    <div v-html="author.bio"></div> <!-- L5 命中 v-html -->
    <p v-text="author.name"></p> <!-- L6 v-text 安全 -->
  </div>
</template>
<script>
export default {
  props: ['title', 'author'],
};
</script>
