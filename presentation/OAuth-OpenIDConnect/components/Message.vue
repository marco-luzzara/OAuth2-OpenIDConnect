<script lang="ts">
export default {
    props: ['direction']
}
</script>

<template>
    <div style="display: flex; flex-direction: row; align-items: center; width: 100%; margin-bottom: 3%;">
        <div class="arrow-left" v-if="direction === 'left'"></div>
        <!-- <ic-baseline-keyboard-arrow-left v-if="direction === 'left'" class="text-5xl" /> -->
        <div style="border: 0.15em solid white; padding: 1%; width: 100%; justify-content: center; align-items: center;"
            class="flex flex-col">
            <slot />
        </div>
        <div class="arrow-right" v-if="direction === 'right'"></div>
    </div>
</template>

<style scoped>
.arrow-right {
    width: 0px;
    height: 0px;
    border-top: 5vh solid transparent;
    border-bottom: 5vh solid transparent;

    border-left: 2vw solid white;
}

.arrow-left {
    width: 0px;
    height: 0px;
    border-top: 5vh solid transparent;
    border-bottom: 5vh solid transparent;

    border-right: 2vw solid white;
}
</style>