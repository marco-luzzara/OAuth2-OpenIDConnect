<script lang="ts">
export default {
    props: ['title']
}
</script>

<template>
    <div style="height: 100%; display: flex; flex-direction: column; align-items: center;">
        <h4>{{ title }}</h4>
        <hr style="width: 2vm; height: 100%; background-color: white;" />
    </div>
</template>