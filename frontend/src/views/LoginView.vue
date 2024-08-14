<template>
    <main class="flex items-center justify-center w-full h-screen border border-black">
        <section class="flex w-4/6 h-4/6">
            <div class="flex flex-col items-center space-y-2  w-3/6 h-full border-r border-black">
                <h1 class="text-xl font-semibold mb-16">Auth</h1>
                <div class="flex justify-start w-3/6">
                <label for="" class="w-full text-xs">Email</label>
                </div>
                <input type="email" class="border border-black outline-none rounded p-2 w-3/6">
                <div class="flex justify-start w-3/6">
                <label for="" class="w-full text-xs">Password</label>
                </div>
                <input type="password" class="border border-black outline-none rounded p-2 w-3/6">
                <input type="button" value="Login" class="border border-black outline-none rounded p-2 w-3/6">

            </div>
            <div class="flex flex-col items-center space-y-2 w-3/6 h-full">
                <h1 class="text-xl font-semibold mb-16">OAuth2</h1>
                <button class="border border-black outline-none rounded p-2 w-3/6">Login using Google</button>
                <button class="border border-black outline-none rounded p-2 w-3/6">Login using Github</button>
                <button class="border border-black outline-none rounded p-2 w-3/6">Login using Facebook</button>
                <button class="border border-black outline-none rounded p-2 w-3/6">Login using LinkedIn</button>

                

            </div>
        </section>
    </main>
</template>
