Trigger bot for CS:GO
=====================

**No support will be provided for any community related examples.**

Credits goes to Snacky_.

Original source code: github_

.. _Snacky: https://github.com/Snaacky
.. _github: https://github.com/Snaacky/Sapphire

Warning
-------

This comes, "as it" with no guarantees regarding its standing with VAC.

Use this code at your own risk and be aware that **using any sort of hack will resolve in having your steam_id banned**

Snippet
-------

.. code-block:: python

    import keyboard
    import pymem
    import pymem.process
    import time
    from win32gui import GetWindowText, GetForegroundWindow

    dwEntityList = (0x4D4B104)
    dwForceAttack = (0x317C6EC)
    dwLocalPlayer = (0xD36B94)
    m_fFlags = (0x104)
    m_iCrosshairId = (0xB3D4)
    m_iTeamNum = (0xF4)

    trigger_key = "shift"


    def main():
        print("Sapphire has launched.")
        pm = pymem.Pymem("csgo.exe")
        client = pymem.process.module_from_name(pm.process_handle, "client.dll").lpBaseOfDll

        while True:
            if not keyboard.is_pressed(trigger_key):
                time.sleep(0.1)

            if not GetWindowText(GetForegroundWindow()) == "Counter-Strike: Global Offensive":
                continue

            if keyboard.is_pressed(trigger_key):
                player = pm.read_int(client + dwLocalPlayer)
                entity_id = pm.read_int(player + m_iCrosshairId)
                entity = pm.read_int(client + dwEntityList + (entity_id - 1) * 0x10)

                entity_team = pm.read_int(entity + m_iTeamNum)
                player_team = pm.read_int(player + m_iTeamNum)

                if entity_id > 0 and entity_id <= 64 and player_team != entity_team:
                    pm.write_int(client + dwForceAttack, 6)

                time.sleep(0.006)


    if __name__ == '__main__':
        main()
