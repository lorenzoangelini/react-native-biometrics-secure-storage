import { NativeModules } from 'react-native';
import {
  BiometricsSecureStorage as BiometricsSecureStorageInterface,
  BiometricsError,
  BiometricsTypes,
  BiometricsInfo,
} from './BiometricsSecureStorage';

const { BiometricsSecureStorage } = NativeModules;

export default BiometricsSecureStorage as BiometricsSecureStorageInterface;

export { BiometricsError, BiometricsTypes, BiometricsInfo };
