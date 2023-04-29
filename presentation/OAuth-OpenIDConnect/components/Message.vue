<script lang="ts">
export default {
    props: ['direction']
}
</script>

<template>
    <div style="display: flex; flex-direction: row; align-items: center;">
        <ic-baseline-keyboard-arrow-left v-if="direction === 'left'" class="text-5xl" />
        <slot />
        <ic-baseline-keyboard-arrow-right v-if="direction === 'right'" class="text-5xl" />
    </div>
</template>