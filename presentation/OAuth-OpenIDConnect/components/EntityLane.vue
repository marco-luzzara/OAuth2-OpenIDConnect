<script lang="ts">
export default {
    props: ['title']
}
</script>

<template>
    <div style="height: auto; width: 15%; display: flex; flex-direction: column; align-items: center; align-self: stretch;">
        <h4 style="text-align: center">{{ title }}</h4>
        <hr style="width: 0.3vw; height: 100%; background-color: white;" />
    </div>
</template>