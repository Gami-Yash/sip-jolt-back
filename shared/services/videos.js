import { db } from '../db.js';
import { instructionalVideos } from '../schema.js';
import { eq } from 'drizzle-orm';

export const ALL_VIDEO_STEPS = [
  { stepId: 'ARRIVAL_SAFETY', wizardType: 'weekly', title: 'Check the Area', description: 'Is trash touching the machine? Are the vents blocked? Clear it away.' },
  { stepId: 'SCREEN_CHECK', wizardType: 'weekly', title: 'Clean the Screen', description: 'Wipe the touch screen with a cloth to remove fingerprints.' },
  { stepId: 'LEAK_BEHIND', wizardType: 'weekly', title: 'Check the Floor', description: 'Look behind the machine. Is the floor wet?' },
  { stepId: 'LEAK_FLOOR_MACHINE', wizardType: 'weekly', title: 'Check Inside', description: 'Open the bottom door. Shine your light inside. Is it dry?' },
  { stepId: 'WASTE_BUCKETS', wizardType: 'weekly', title: 'Dirty Water Buckets', description: 'Empty them. Rinse them. Put them back with the correct tubes inside.' },
  { stepId: 'GRIND_BIN', wizardType: 'weekly', title: 'Coffee Grounds Bin', description: 'Unlock cup holder. Swing it open like a door. Take out bin. Wash it.' },
  { stepId: 'SPLASHGUARD_WIPE', wizardType: 'weekly', title: 'Splashguard', description: 'Wipe the plastic wall behind the coffee nozzles.' },
  { stepId: 'DRIP_TRAY_WIPE', wizardType: 'weekly', title: 'Drip Tray', description: 'Wipe the tray clean.' },
  { stepId: 'CUPS_LIDS', wizardType: 'weekly', title: 'Cups & Lids', description: 'Are cup stacks low? Fill them. Are lids low? Add more.' },
  { stepId: 'BEAN_HOPPER', wizardType: 'weekly', title: 'Bean Hopper', description: 'Is it low? Refill it. Pull the plastic tab OUT after.' },
  { stepId: 'POWDER_INTRO', wizardType: 'weekly', title: '7 Powder Boxes', description: 'Look at each box. Only refill if less than half full.' },
  { stepId: 'POWDER_WIPE', wizardType: 'weekly', title: 'Wipe Powder Area', description: 'Wipe away spilled powder around the canisters.' },
  { stepId: 'SYRUP_INTRO', wizardType: 'weekly', title: 'Check Syrup Lines', description: 'Make sure all syrup bottles are connected and not empty.' },
  { stepId: 'DIGITAL_LOG', wizardType: 'weekly', title: 'Digital Service Log', description: 'Check the machine screen for any alerts.' },
  { stepId: 'ERROR_CHECK', wizardType: 'weekly', title: 'Error Screen Check', description: 'Is there a red/orange error banner on the screen?' },
  { stepId: 'TEST_DRINK', wizardType: 'weekly', title: 'Test Drink', description: 'Make a test drink to verify everything works.' },
  { stepId: 'WASTE_BUCKETS_MONTHLY', wizardType: 'monthly', title: 'Dirty Water Buckets (Deep)', description: 'Empty, rinse, and sanitize the waste buckets thoroughly.' },
  { stepId: 'GRIND_BIN_MONTHLY', wizardType: 'monthly', title: 'Coffee Grounds Bin (Deep)', description: 'Unlock cup holder. Take out bin. Wash and sanitize it.' },
  { stepId: 'CANISTER_DISASSEMBLY', wizardType: 'monthly', title: 'Remove All Canisters', description: 'Rotate spout up. Remove canister. Pull out auger/wheel from inside.' },
  { stepId: 'GRINDER_DEEP_CLEAN', wizardType: 'monthly', title: 'Grinder Baffles & Dust Cover', description: 'Remove grinder dust cover. Remove residue baffle. Brush away all hidden coffee grounds.' },
  { stepId: 'DRIP_TRAY_REMOVAL', wizardType: 'monthly', title: 'Drip Tray Removal', description: 'Remove the drip tray completely. Wash and sanitize it.' },
  { stepId: 'MIXER_SYSTEM', wizardType: 'monthly', title: 'Mixer System', description: 'Clean the mixer paddles and chamber.' },
  { stepId: 'CUP_PATH_CLEAN', wizardType: 'monthly', title: 'Cup Path Clean', description: 'Clean the cup dispensing path and sensors.' },
  { stepId: 'DESCALING_PROGRAM', wizardType: 'monthly', title: 'Descaling Program', description: 'Run the descaling program with citric acid solution.' },
  { stepId: 'BREWER_REMOVAL', wizardType: 'monthly', title: 'Brewer Removal & Clean', description: 'Remove the brew unit. Clean and rinse all parts.' }
];

export function getStepDefinition(stepId) {
  return ALL_VIDEO_STEPS.find(s => s.stepId === stepId) || null;
}

export async function getAllUploadedVideos() {
  try {
    return await db.select().from(instructionalVideos);
  } catch (error) {
    console.error('[VideoService] getAllUploaded error:', error.message);
    return [];
  }
}

export async function getVideoByStepId(stepId) {
  try {
    const [video] = await db.select()
      .from(instructionalVideos)
      .where(eq(instructionalVideos.stepId, stepId))
      .limit(1);
    return video || null;
  } catch (error) {
    console.error('[VideoService] getByStepId error:', error.message);
    throw new Error(`Database error fetching video: ${error.message}`);
  }
}

export async function getAllVideoStepsWithStatus() {
  try {
    const uploadedVideos = await getAllUploadedVideos();
    const videoMap = new Map();
    uploadedVideos.forEach(v => videoMap.set(v.stepId, v));
    
    const stepsWithStatus = ALL_VIDEO_STEPS.map(step => {
      const uploaded = videoMap.get(step.stepId);
      return {
        ...step,
        hasVideo: !!uploaded?.videoUrl,
        videoUrl: uploaded?.videoUrl || null,
        objectPath: uploaded?.objectPath || null,
        uploadedAt: uploaded?.uploadedAt || null,
        uploadedBy: uploaded?.uploadedBy || null
      };
    });
    
    return {
      weekly: stepsWithStatus.filter(s => s.wizardType === 'weekly'),
      monthly: stepsWithStatus.filter(s => s.wizardType === 'monthly'),
      totalSteps: ALL_VIDEO_STEPS.length,
      uploadedCount: uploadedVideos.filter(v => v.videoUrl).length
    };
  } catch (error) {
    console.error('[VideoService] getAllWithStatus error:', error.message);
    throw new Error(`Database error fetching video steps: ${error.message}`);
  }
}

export async function saveVideoMetadata(stepId, data) {
  const stepDef = getStepDefinition(stepId);
  if (!stepDef) {
    throw new Error(`Invalid step ID: ${stepId}`);
  }
  
  const { videoUrl, objectPath, fileSize, durationSeconds, uploadedBy } = data;
  
  try {
    const existing = await getVideoByStepId(stepId);
    
    if (existing) {
      const [updated] = await db.update(instructionalVideos)
        .set({
          videoUrl,
          objectPath,
          fileSize,
          durationSeconds,
          uploadedBy,
          uploadedAt: new Date(),
          updatedAt: new Date()
        })
        .where(eq(instructionalVideos.stepId, stepId))
        .returning();
      
      return { video: updated, action: 'updated' };
    } else {
      const [created] = await db.insert(instructionalVideos)
        .values({
          stepId,
          wizardType: stepDef.wizardType,
          title: stepDef.title,
          description: stepDef.description,
          videoUrl,
          objectPath,
          fileSize,
          durationSeconds,
          uploadedBy,
          uploadedAt: new Date()
        })
        .returning();
      
      return { video: created, action: 'created' };
    }
  } catch (error) {
    console.error('[VideoService] saveMetadata error:', error.message);
    throw new Error(`Database error saving video: ${error.message}`);
  }
}

export async function deleteVideo(stepId) {
  try {
    const [updated] = await db.update(instructionalVideos)
      .set({
        videoUrl: null,
        objectPath: null,
        fileSize: null,
        durationSeconds: null,
        uploadedBy: null,
        uploadedAt: null,
        updatedAt: new Date()
      })
      .where(eq(instructionalVideos.stepId, stepId))
      .returning();
    
    return updated;
  } catch (error) {
    console.error('[VideoService] delete error:', error.message);
    throw new Error(`Database error deleting video: ${error.message}`);
  }
}
