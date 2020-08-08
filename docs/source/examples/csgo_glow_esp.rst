External glow ESP for CS:GO
===========================

**No support will be provided for any community related examples.**

Credits goes to Snacky_.

Original source code: github_

.. _Snacky: https://github.com/Snaacky
.. _github: https://github.com/Snaacky/Diamond

Warning
-------

This comes, "as it" with no guarantees regarding its standing with VAC.

Use this code at your own risk and be aware that **using any sort of hack will resolve in having your steam_id banned**

Snippet
-------

.. code-block:: python

    import pymem
    import pymem.process

    dwEntityList = (0x4D4B104)
    dwGlowObjectManager = (0x5292F20)
    m_iGlowIndex = (0xA428)
    m_iTeamNum = (0xF4)


    def main():
        print("Diamond has launched.")
        pm = pymem.Pymem("csgo.exe")
        client = pymem.process.module_from_name(pm.process_handle, "client.dll").lpBaseOfDll

        while True:
            glow_manager = pm.read_int(client + dwGlowObjectManager)

            for i in range(1, 32):  # Entities 1-32 are reserved for players.
                entity = pm.read_int(client + dwEntityList + i * 0x10)

                if entity:
                    entity_team_id = pm.read_int(entity + m_iTeamNum)
                    entity_glow = pm.read_int(entity + m_iGlowIndex)

                    if entity_team_id == 2:  # Terrorist
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0x4, float(1))   # R
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0x8, float(0))   # G
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0xC, float(0))   # B
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0x10, float(1))  # Alpha
                        pm.write_int(glow_manager + entity_glow * 0x38 + 0x24, 1)           # Enable glow

                    elif entity_team_id == 3:  # Counter-terrorist
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0x4, float(0))   # R
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0x8, float(0))   # G
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0xC, float(1))   # B
                        pm.write_float(glow_manager + entity_glow * 0x38 + 0x10, float(1))  # Alpha
                        pm.write_int(glow_manager + entity_glow * 0x38 + 0x24, 1)           # Enable glow


    if __name__ == '__main__':
        main()
