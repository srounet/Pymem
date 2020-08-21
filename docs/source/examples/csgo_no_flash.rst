No flash cheat for CS:GO
========================

**No support will be provided for any community related examples.**

Credits goes to Snacky_.

Original source code: github_

.. _Snacky: https://github.com/Snaacky
.. _github: https://github.com/Snaacky/Emerald

Warning
-------

This comes, "as it" with no guarantees regarding its standing with VAC.

Use this code at your own risk and be aware that **using any sort of hack will resolve in having your steam_id banned**

Snippet
-------

.. code-block:: python

    import pymem
    import pymem.process
    import time

    dwLocalPlayer = (0xD36B94)
    m_flFlashMaxAlpha = (0xA40C)


    def main():
        print("Emerald has launched.")
        pm = pymem.Pymem("csgo.exe")
        client = pymem.process.module_from_name(pm.process_handle, "client.dll").lpBaseOfDll

        while True:
            player = pm.read_int(client + dwLocalPlayer)
            if player:
                flash_value = player + m_flFlashMaxAlpha
                if flash_value:
                    pm.write_float(flash_value, float(0))
            time.sleep(1)


    if __name__ == '__main__':
        main()
