<script lang="ts">
export default {
    props: ['title']
}
</script>

<template>
    <div style="height: 100%; display: flex; flex-direction: column; align-items: center;">
        <h4>{{ title }}</h4>
        <hr style="width: 0.5vw; height: 100%; background-color: white;" />
    </div>
</template>